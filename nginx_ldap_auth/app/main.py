from pathlib import Path
from typing import Annotated, Any, cast

from fastapi import Depends, FastAPI, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi_csrf_protect import CsrfProtect
from fastapi_csrf_protect.exceptions import CsrfProtectError
from pydantic import AnyUrl, Field
from pydantic_settings import BaseSettings
from starsessions import (
    InMemoryStore,
    SessionStore,
    get_session_handler,
    load_session,
)
from starsessions.stores.redis import RedisStore

from nginx_ldap_auth import __version__
from nginx_ldap_auth.settings import Settings

from ..logging import get_logger
from .forms import LoginForm
from .middleware import SessionMiddleware
from .models import User

current_dir: Path = Path(__file__).resolve().parent
static_dir: Path = current_dir / "static"
templates_dir: Path = current_dir / "templates"


settings = Settings()

# --------------------------------------
# Session Store
# --------------------------------------

if settings.session_backend == "memory":
    store: SessionStore = InMemoryStore()
    get_logger().info("session.store", backend=settings.session_backend)
elif settings.session_backend == "redis":
    store = RedisStore(
        str(settings.redis_url),
        prefix=settings.redis_prefix,
        gc_ttl=settings.session_max_age,
    )
    redis_url = cast(AnyUrl, settings.redis_url)
    get_logger().info(
        "session.store",
        backend=settings.session_backend,
        server=redis_url.host,
        port=redis_url.port,
        db=redis_url.path,
    )

# --------------------------------------
# CSRF Protection
# --------------------------------------


class CsrfSettings(BaseSettings):
    #: The secret key to use for CSRF tokens
    secret_key: str = Field(validation_alias="CSRF_SECRET_KEY")
    #: We'll set the SameSite attribute on our CSRF cookies to this value
    cookie_samesite: str = "lax"
    #: Set our CSRF cookie to be secure
    cookie_secure: bool = True
    #: Set the maximum age of our CSRF cookie to 5 minutes
    max_age: int = 300
    #: Cookie name
    cookie_key: str = f"{settings.cookie_name}_csrf"
    #: Cookie domain
    cookie_domain: str | None = settings.cookie_domain
    #: Token location for validation -- in the csrf_token field in the body
    token_location: str = "body"  # noqa: S105
    #: The key to use for the CSRF token -- the name of the field in the body
    token_key: str = "csrf_token"  # noqa: S105


@CsrfProtect.load_config
def get_csrf_config():
    return CsrfSettings()


# --------------------------------------
# The FastAPI app
# --------------------------------------

app = FastAPI(title="nginx_ldap_auth", debug=settings.debug, version=__version__)
app.mount("/auth/static", StaticFiles(directory=str(static_dir)), name="static")
app.add_middleware(
    SessionMiddleware,
    store=store,
    cookie_name=settings.cookie_name,
    lifetime=settings.session_max_age,
)
get_logger().info(
    "session.setup.complete",
    backend=settings.session_backend,
    cookie_name=settings.cookie_name,
    cookie_domain=settings.cookie_domain,
    max_age=settings.session_max_age,
    rolling=settings.use_rolling_session,
)
templates = Jinja2Templates(directory=str(templates_dir))


# --------------------------------------
# Startup and Shutdown Events
# --------------------------------------


@app.on_event("startup")
async def startup() -> None:
    """
    Create the LDAP connection pool when we start up.
    """
    await User.objects.create_pool()


@app.on_event("shutdown")
async def shutdown() -> None:
    """
    Close the LDAP connection pool when we shut down.
    """
    await User.objects.cleanup()


# --------------------------------------
# Helper Functions
# --------------------------------------


async def kill_session(request: Request) -> None:
    """
    Kill the current session.

    This means empty the session object of all contents, and delete it from the
    backend.

    Args:
        request: The request object

    """
    for key in list(request.session.keys()):
        del request.session[key]
    await get_session_handler(request).destroy()


# --------------------------------------
# Views
# --------------------------------------


@app.get("/auth/login", response_model=None, name="login")
async def login(
    request: Request,
    csrf_protect: Annotated[CsrfProtect, Depends()],
    service: str = "/",
) -> HTMLResponse | RedirectResponse:
    """
    If the user is already logged in -- they have a session cookie, the session
    the cookie points to exists, and the "username" key in the session exists --
    redirect to the URI named by the ``service``, query paremeter, defaulting to
    ``/`` if that is not present.  Otherwise, render the login page with a fresh
    CSRF token, storing ``service`` in the login form as a hidden field.

    If the header ``X-Auth-Realm`` is set, use that as the title for the login
    page.  Otherwise use
    :py:attr:`nginx_ldap_auth.settings.Settings.auth_realm`.

    Args:
        request: The request object
        csrf_protect: The CSRF protection dependency

    Keyword Args:
        service: redirect the user to this URL after successful login

    Returns:
        If the user is already logged in, a redirect response to the service URL.
        Otherwise, a rendered login page.

    """
    csrf_token, signed_token = csrf_protect.generate_csrf_tokens()
    auth_realm = request.headers.get("x-auth-realm", settings.auth_realm)
    _logger = get_logger(request)
    _logger.info("auth.login.start", target=service)
    await load_session(request)
    if request.session.get("username"):
        session_id = get_session_handler(request).session_id
        _logger.info(
            "auth.login.success.already_logged_in",
            username=request.session["username"],
            session_id=session_id,
            target=service,
        )
        # semgrep-reason:
        #    The service URL is passed in by nginx, and the user cannot directly
        #    reach this URL unless nginx says it needs to, so this is safe.
        # nosemgrep: tainted-redirect-fastapi  # noqa: ERA001
        return RedirectResponse(url=service)
    # semgrep-reason:
    #    The service URL is passed in by nginx, and the user cannot directly
    #    reach this URL unless nginx says it needs to, so this is safe.
    # nosemgrep: tainted-direct-response-fastapi  # noqa: ERA001
    response = templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            "site_title": auth_realm,
            "service": service,
            "csrf_token": csrf_token,
        },
    )
    csrf_protect.set_csrf_cookie(signed_token, response)
    return response


@app.post("/auth/login", response_model=None, name="login_handler")
async def login_handler(
    request: Request,
    csrf_protect: Annotated[CsrfProtect, Depends()],
) -> HTMLResponse | RedirectResponse:
    """
    Process our user's login request.  Validate the CSRF token from the login form,
    and attempt to bind to our LDAP server with the supplied username and password.
    If authentication is successful, redirect to the value of the ``service``
    hidden input field on our form.  If authentication fails, display the login
    form again.

    If the header ``X-Auth-Realm`` is set, use that as the title for the login
    page.  Otherwise use
    :py:attr:`nginx_ldap_auth.settings.Settings.auth_realm`.

    Side Effects:
        If authentication is successful, the user's username is stored in the
        session.

        No matter what, the CSRF cookie is unset to prevent token reuse.

    Args:
        request: The request object
        csrf_protect: The CSRF protection dependency

    Returns:
        A redirect response to the service URL if authentication is successful.
        Otherwise, a rendered login page.

    """
    auth_realm = request.headers.get("x-auth-realm", settings.auth_realm)
    await csrf_protect.validate_csrf(request)
    form = LoginForm(request)
    form.site_title = auth_realm
    await form.load_data()
    if await form.is_valid():
        await load_session(request)
        request.session["username"] = form.username
        response: HTMLResponse | RedirectResponse = RedirectResponse(
            url=form.service, status_code=status.HTTP_302_FOUND
        )
    else:
        response = templates.TemplateResponse("login.html", form.__dict__)
    csrf_protect.unset_csrf_cookie(response)  # prevent token reuse
    return response


@app.get("/auth/logout", response_model=None, name="logout")
async def logout(request: Request) -> RedirectResponse:
    """
    Log the user out by invalidating the sesision, and redirect them to the
    login page.

    Args:
        request: The request object

    Returns:
        A redirect response to the login page.

    """
    _logger = get_logger(request)
    await load_session(request)
    if username := request.session.get("username"):
        await kill_session(request)
        _logger.info("auth.logout", username=username)
    return RedirectResponse(url="/auth/login?service=/")


@app.get("/check")
async def check_auth(request: Request, response: Response) -> dict[str, Any]:
    """
    Ensure the user is still authorized.  If the user is authorized, return
    200 OK, otherwise return 401 Unauthorized.

    The user is authorized if the cookie exists, the session the cookie refers
    to exists, and the ``username`` key in the settings is set.  Additionally,
    the user must still exist in LDAP, and if
    :py:attr:`nginx_ldap_auth.settings.Settings.ldap_authorization_filter` is
    not ``None``, the user must also match the filter.

    Side Effects:
        If the user is not authorized, the session is destroyed, and the user is
        status_code on ``response`` is set to 401.

    Args:
        request: The request object
        response: The response object

    Returns:
        An empty dictionary.

    """
    if request.cookies.get(settings.cookie_name):
        await load_session(request)
        if request.session.get("username"):
            # We have a valid session
            if not await User.objects.get(request.session["username"]):
                # The user does not exist in LDAP; log them out
                await kill_session(request)
            if not await User.objects.is_authorized(request.session["username"]):
                # The user is no longer authorized; log them out
                await kill_session(request)
            return {}
        # Destroy the session because it is not valid
        await kill_session(request)
    # Force the user to authenticate
    response.headers["Cache-Control"] = "no-cache"
    response.status_code = status.HTTP_401_UNAUTHORIZED
    return {}


@app.exception_handler(CsrfProtectError)
def csrf_protect_exception_handler(request: Request, exc: CsrfProtectError) -> Response:
    """
    Handle CSRF protection errors.  All we're going to do is redirect the user
    back to the login page after logging the error.

    Args:
        request: The request object
        exc: The exception object from the CSRF protection middleware

    Returns:
        A redirect response to the login page.

    """
    _logger = get_logger(request)
    _logger.error("auth.login.csrf.error", error=str(exc))
    return RedirectResponse(
        url=app.url_path_for("login"), status_code=status.HTTP_302_FOUND
    )
