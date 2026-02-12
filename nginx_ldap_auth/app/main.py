from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Any, Final, cast

import duo_universal
from bonsai import LDAPError
from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi_csrf_protect import CsrfProtect
from fastapi_csrf_protect.exceptions import CsrfProtectError
from pydantic import AnyUrl, Field
from pydantic_settings import BaseSettings
from starlette.concurrency import run_in_threadpool
from starsessions import (
    InMemoryStore,
    SessionStore,
    get_session_handler,
    load_session,
)
from starsessions.stores.redis import RedisStore

from nginx_ldap_auth import __version__
from nginx_ldap_auth.exc import ImproperlyConfigured
from nginx_ldap_auth.settings import Settings
from nginx_ldap_auth.validators import validate_ldap_search_filter

from ..logging import get_logger
from .forms import LoginForm
from .middleware import ExceptionLoggingMiddleware, SessionMiddleware
from .models import User

current_dir: Path = Path(__file__).resolve().parent
static_dir: Path = current_dir / "static"
templates_dir: Path = current_dir / "templates"


settings = Settings()

#: These paths are excluded from Duo authentication
DUO_AUTH_PATHS: Final[set[str]] = {
    "/auth/login",
    "/auth/logout",
    "/auth/duo/callback",
    "/auth/duo",
    "/status",
    "/check",
}

# --------------------------------------
# Session Store
# --------------------------------------

if settings.session_backend == "memory":
    store: SessionStore = InMemoryStore()
    get_logger().info("session.store", backend=settings.session_backend)
elif settings.session_backend == "redis":
    # If session_max_age is 0 (session-only cookie), we still need a TTL for Redis.
    # We'll use 30 days as a default gc_ttl in that case.
    gc_ttl = (
        settings.session_max_age if settings.session_max_age > 0 else 3600 * 24 * 30
    )
    store = RedisStore(
        str(settings.redis_url),
        prefix=settings.redis_prefix,
        gc_ttl=gc_ttl,
    )
    redis_url = cast("AnyUrl", settings.redis_url)
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
    """
    Settings for CSRF protection. Used by the `fastapi-csrf-protect` library.

    See: https://github.com/fastapi-csrf-protect/fastapi-csrf-protect
    """

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


@asynccontextmanager
async def lifespan(app: FastAPI):  # noqa: ARG001
    """
    Handle startup and shutdown events.
    """
    # Startup: Create the LDAP connection pool
    await User.objects.create_pool()
    yield
    # Shutdown: Close the LDAP connection pool
    await User.objects.cleanup()


app = FastAPI(
    title="nginx_ldap_auth",
    debug=settings.debug,
    version=__version__,
    lifespan=lifespan,
)
app.mount("/auth/static", StaticFiles(directory=str(static_dir)), name="static")

# Register session middleware
app.add_middleware(
    SessionMiddleware,
    store=store,
    cookie_name=settings.cookie_name,
    lifetime=settings.session_max_age,
)
# Outermost middleware that will log all exceptions not caught by other
# middleware.
app.add_middleware(ExceptionLoggingMiddleware)


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


async def save_session(request: Request) -> None:
    """
    Save the session to the backend.
    """
    await get_session_handler(request).save(remaining_time=settings.session_max_age)


def check_required_headers(request: Request) -> None:
    """
    Check that the required headers are present in the request.

    - ``X-Proto-Scheme``
    - ``Host``

    Args:
        request: The request object

    Raises:
        AssertionError: If the required headers are not present

    """
    logger = get_logger(request)
    if request.headers.get("x-proto-scheme") is None:
        logger.error("check_required_headers.missing", header="X-Proto-Scheme")
        msg = (
            "'proxy_set_header X-Proto-Scheme $scheme' is required in your /auth "
            "location in your nginx configuration file."
        )
        raise ImproperlyConfigured(msg)
    # There's a problem here -- we'll always get the host header from the
    # request, since if we don't use proxy_set_header, we'll get the host name
    # from the proxy_pass line.  Thus, we use the X-Host header to get the host
    # name from the request headers.
    if request.headers.get("x-host") is None:
        logger.error("check_required_headers.missing", header="X-Host")
        msg = (
            "'proxy_set_header X-Host $host' is required in your /auth "
            "location in your nginx configuration file."
        )
        raise ImproperlyConfigured(msg)
    logger.debug(
        "check_required_headers.success",
        x_proto_scheme=request.headers.get("x-proto-scheme"),
        x_host=request.headers.get("x-host"),
    )


async def validate_service_url(request: Request, service: str | None = None) -> str:
    """
    Validate the service URL requested by the user.
    """
    check_required_headers(request)
    base_url = (
        f"{request.headers.get('x-proto-scheme')}://{request.headers.get('x-host')}"
    )
    if not service:
        service = request.query_params.get("service", "/")
    if service.startswith((base_url, "/")):
        return service
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid URL requested"
    )


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
    service = await validate_service_url(request, service=service)
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
    try:
        await csrf_protect.validate_csrf(request)
    except CsrfProtectError as e:
        get_logger(request).error("auth.login.csrf.error", error=str(e))
        return RedirectResponse(
            url=app.url_path_for("login"), status_code=status.HTTP_302_FOUND
        )
    form = LoginForm(request)
    form.site_title = auth_realm
    await form.load_data()
    if await form.is_valid():
        await load_session(request)
        request.session["username"] = form.username
        request.session["duo_authenticated"] = False
        if settings.duo_enabled:
            service = await validate_service_url(request, service=form.service)
            response = RedirectResponse(
                # semgrep-reason:
                #    The service URL is sanitized by the validate_service_url function,
                #    so we can safely redirect to it.
                # nosemgrep: tainted-redirect-fastapi  # noqa: ERA001
                url=f"/auth/duo?service={service}",
                status_code=status.HTTP_302_FOUND,
            )
        else:
            response = RedirectResponse(
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


@app.get("/auth/duo", response_model=None, name="duo")
async def duo(request: Request, service: str = "/") -> RedirectResponse:
    """
    Initiate the Duo MFA workflow.

    Args:
        request: The request object
        service: The service to redirect to after successful MFA

    Returns:
        A redirect response to the Duo Universal Prompt.

    """
    service = await validate_service_url(request, service=service)
    if not settings.duo_enabled:
        # semgrep-reason:
        #    The service URL is sanitized by the validate_service_url function,
        #    so we can safely redirect to it.
        # nosemgrep: tainted-redirect-fastapi  # noqa: ERA001
        return RedirectResponse(url=service)
    _logger = get_logger(request)
    await load_session(request)
    _logger.info("auth.duo.session", session=request.session)
    username = request.session.get("username")
    if not username:
        _logger.warning("auth.duo.no_username")
        return RedirectResponse(
            # semgrep-reason:
            #    The service URL is sanitized by the validate_service_url function,
            #    so we can safely redirect to it.
            # nosemgrep: tainted-redirect-fastapi  # noqa: ERA001
            url=f"/auth/login?service={service}",
            status_code=status.HTTP_302_FOUND,
        )
    check_required_headers(request)
    # Get the base URL from the request headers
    base_url = (
        f"{request.headers.get('x-proto-scheme')}://{request.headers.get('x-host')}"
    )
    redirect_uri = f"{base_url}/auth/duo/callback"
    _logger.debug("auth.duo.redirect_uri", redirect_uri=redirect_uri)
    # Initialize Duo client
    try:
        duo_client = duo_universal.Client(
            client_id=cast("str", settings.duo_ikey),
            client_secret=cast("str", settings.duo_skey),
            host=cast("str", settings.duo_host),
            redirect_uri=redirect_uri,
        )
    except (ValueError, TypeError) as e:
        _logger.exception("auth.duo.client_creation_failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create Duo client",
        ) from e

    # Perform health check
    try:
        duo_client.health_check()
    except duo_universal.DuoException as e:
        _logger.exception("auth.duo.health_check_failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Duo health check failed",
        ) from e
    else:
        _logger.debug("auth.duo.health_check.success")
    # Generate state and store it in session
    state = duo_client.generate_state()
    request.session["duo_state"] = state
    request.session["duo_service"] = service
    _logger.info("auth.duo.state_saved", state=state, service=service)
    await save_session(request)
    try:
        # Create auth URL and redirect
        auth_url = duo_client.create_auth_url(username, state)
    except (ValueError, TypeError, duo_universal.DuoException) as e:
        _logger.exception("auth.duo.error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to initiate MFA",
        ) from e
    else:
        _logger.info("auth.duo.redirect.success", username=username, target=service)
        # semgrep-reason:
        #    The auth URL is sanitized by the Duo client,
        #    so we can safely redirect to it.
        # nosemgrep: tainted-redirect-fastapi  # noqa: ERA001
        return RedirectResponse(url=auth_url)


@app.get("/auth/duo/callback", response_model=None, name="duo_callback")
async def duo_callback(
    request: Request,
    duo_code: str | None = None,
    state: str | None = None,
) -> RedirectResponse:
    """
    Handle the callback from Duo.

    Args:
        request: The request object
        duo_code: The authorization code from Duo
        state: The state parameter from Duo

    Returns:
        A redirect response to the original service URL.

    """
    _logger = get_logger(request)

    state = request.query_params.get("state")

    await load_session(request)
    # Session data
    username = request.session.get("username")
    stored_state = request.session.get("duo_state")
    service = request.session.get("duo_service", "/")
    service = await validate_service_url(request, service=service)

    if not state:
        _logger.warning("auth.duo.callback.missing_parameters")
        # semgrep-reason:
        #    The service URL is sanitized by the validate_service_url function,
        #    so we can safely redirect to it.
        # nosemgrep: tainted-redirect-fastapi  # noqa: ERA001
        return RedirectResponse(url=f"/auth/login?service={service}")

    if state != stored_state:
        _logger.error(
            "auth.duo.callback.state_mismatch", stored_state=stored_state, state=state
        )
        # semgrep-reason:
        #    The service URL is sanitized by the validate_service_url function,
        #    so we can safely redirect to it.
        # nosemgrep: tainted-redirect-fastapi  # noqa: ERA001
        return RedirectResponse(url=f"/auth/login?service={service}")

    # Get the base URL from the request headers
    base_url = (
        f"{request.headers.get('x-proto-scheme')}://{request.headers.get('x-host')}"
    )
    redirect_uri = f"{base_url}/auth/duo/callback"
    _logger.debug("auth.duo.callback.redirect_uri", redirect_uri=redirect_uri)
    # Initialize Duo client
    duo_client = duo_universal.Client(
        client_id=cast("str", settings.duo_ikey),
        client_secret=cast("str", settings.duo_skey),
        host=cast("str", settings.duo_host),
        redirect_uri=redirect_uri,
    )

    try:
        # Exchange code for 2FA result
        # The duo_client call is synchronous, so we need to run it in a threadpool.
        await run_in_threadpool(
            duo_client.exchange_authorization_code_for_2fa_result,
            duo_code,
            username,
        )
    except duo_universal.DuoException as e:
        _logger.exception("auth.duo.callback.exchange_failed", error=str(e))
        # semgrep-reason:
        #    The service URL is sanitized by the validate_service_url function,
        #    so we can safely redirect to it.
        # nosemgrep: tainted-redirect-fastapi  # noqa: ERA001
        return RedirectResponse(url=f"/auth/login?service={service}")
    else:
        _logger.info(
            "auth.duo.callback.exchange_success", username=username, target=service
        )

    # Success!
    request.session["duo_authenticated"] = True

    # Clean up Duo-specific session data
    if "duo_state" in request.session:
        del request.session["duo_state"]
    if "duo_service" in request.session:
        del request.session["duo_service"]

    await save_session(request)
    _logger.info("auth.duo.callback.success", username=username, target=service)
    # semgrep-reason:
    #    The service URL is sanitized by the validate_service_url function,
    #    so we can safely redirect to it.
    # nosemgrep: tainted-redirect-fastapi  # noqa: ERA001
    return RedirectResponse(url=service)


@app.get("/check")
async def check_auth(request: Request, response: Response) -> dict[str, Any]:
    """
    Ensure the user is still authorized.  If the user is authorized, return
    200 OK, otherwise return 401 Unauthorized.

    The user is authorized if the cookie exists, the session the cookie refers
    to exists, and the ``username`` key in the settings is set.  Additionally,
    the user must still exist in LDAP, and if
    the ``X-Authorization-Filter`` header (when
    :py:attr:`nginx_ldap_auth.settings.Settings.allow_authorization_filter_header`
    is ``True``) or
    :py:attr:`nginx_ldap_auth.settings.Settings.ldap_authorization_filter` is
    not ``None``, the user must also match the filter.
    The optional header will override the setting when allowed.

    Side Effects:
        If the user is not authorized, the session is destroyed, and the user is
        status_code on ``response`` is set to 401.

    Raises:
        ValueError: The LDAP search filter is not a valid LDAP filter

    Args:
        request: The request object
        response: The response object

    Returns:
        An empty dictionary.

    """
    _logger = get_logger(request)
    cookie_name = request.headers.get("x-cookie-name", settings.cookie_name)
    if request.cookies.get(cookie_name):
        await load_session(request)
        if request.session.get("username"):
            if (
                settings.duo_enabled
                and request.session.get("duo_authenticated") is None
            ):
                await kill_session(request)
                # User is LDAP-authenticated but not Duo-authenticated
                response.status_code = status.HTTP_401_UNAUTHORIZED
                return {}

            # We have a valid session
            if not await User.objects.get(request.session["username"]):
                # The user does not exist in LDAP; log them out
                await kill_session(request)
                response.status_code = status.HTTP_401_UNAUTHORIZED
                return {}
            if settings.allow_authorization_filter_header:
                ldap_authorization_filter: str | None = request.headers.get(
                    "x-authorization-filter", settings.ldap_authorization_filter
                )
                if ldap_authorization_filter:
                    try:
                        validate_ldap_search_filter(
                            ldap_authorization_filter,
                            ldap_username_attribute=settings.ldap_username_attribute,
                            ldap_full_name_attribute=settings.ldap_full_name_attribute,
                        )
                    except ValueError as e:
                        _logger.exception(
                            "auth.check.invalid_authorization_filter", error=str(e)
                        )
                        raise
            else:
                ldap_authorization_filter = settings.ldap_authorization_filter
            if not await User.objects.is_authorized(
                request.session["username"], ldap_authorization_filter
            ):
                # The user is no longer authorized; log them out
                await kill_session(request)
                response.status_code = status.HTTP_401_UNAUTHORIZED
                return {}
            return {}
        # Destroy the session because it is not valid
        await kill_session(request)
    # Force the user to authenticate
    response.headers["Cache-Control"] = "no-cache"
    response.status_code = status.HTTP_401_UNAUTHORIZED
    return {}


@app.get("/status", status_code=status.HTTP_200_OK)
async def app_status(request: Request) -> dict[str, Any]:  # noqa: ARG001
    """
    Return the status of the auth service.

    Args:
        request: The request object

    Returns:
        A tuple containing the status of the auth service and the HTTP status code.
        The status is "ok" if the auth service is successful, otherwise "error".
        The message is the error message if the auth service is not successful.

    """
    return {"status": "ok", "message": "Auth service is running"}


@app.get("/status/ldap", status_code=status.HTTP_200_OK)
async def ldap_status(request: Request, response: Response) -> dict[str, Any]:
    """
    Return the status of the LDAP connection.

    Args:
        request: The request object
        response: The response object

    Returns:
        A tuple containing the status of the LDAP connection and the HTTP status code.
        The status is "ok" if the LDAP connection is successful, otherwise "error".
        The message is the error message if the LDAP connection is not successful.

    """
    logger = get_logger(request)
    # Try to bind to the LDAP server
    try:
        client = User.objects.client()
        if settings.ldap_binddn and settings.ldap_password:
            client.set_credentials(
                "SIMPLE",
                user=settings.ldap_binddn,
                password=settings.ldap_password,
            )
        await client.connect(is_async=True)
    except LDAPError:
        logger.exception(
            "status.ldap.error",
            message="LDAP connection failed during status check",
        )
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        return {
            "status": "error",
            "message": "LDAP connection failed",
        }
    logger.debug(
        "status.ldap.success",
        message="LDAP connection successful during status check",
    )
    return {"status": "ok", "message": "LDAP connection successful"}


@app.get("/nginx_ldap_auth/test")
async def nginx_ldap_auth_test(_: Request, response: Response) -> dict[str, Any]:
    """
    A test endpoint to check if if the auth workflow is working.

    Important:
        This endpoint is only available if
        :attr:`nginx_ldap_auth.settings.Settings.debug` is True.

    Args:
        _: The request object
        response: The response object

    Returns:
        A dictionary containing the status of the test and the HTTP status code,
        or an empty dictionary if the
        :attr:`nginx_ldap_auth.settings.Settings.debug` is False.

    """
    if settings.debug:
        return {"status": "ok", "message": "Auth service worked"}
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
