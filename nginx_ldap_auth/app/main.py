#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
from typing import Annotated, Optional

from fastapi import FastAPI, Header, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starsessions import (
    InMemoryStore,
    SessionStore,
    load_session,
    get_session_handler,
)
from starsessions.stores.redis import RedisStore

from nginx_ldap_auth import __version__
from nginx_ldap_auth.settings import Settings

from ..logging import logger

from .forms import LoginForm
from .middleware import SessionMiddleware
from .models import User

current_dir = os.path.dirname(os.path.abspath(__file__))
static_dir = os.path.join(current_dir, "static")
templates_dir = os.path.join(current_dir, "templates")


settings = Settings()

if settings.session_backend == "memory":
    store: SessionStore = InMemoryStore()
elif settings.session_backend == "redis":
    store = RedisStore(
        settings.redis_url,
        prefix=settings.redis_prefix,
        gc_ttl=settings.session_max_age
    )
logger.info("session.store", backend=settings.session_backend)

app = FastAPI(
    title="nginx_ldap_auth",
    debug=settings.debug,
    version=__version__
)
app.mount("/auth/static", StaticFiles(directory=static_dir), name="static")
app.add_middleware(
    SessionMiddleware,
    store=store,
    cookie_name=settings.cookie_name,
    lifetime=settings.session_max_age
)
templates = Jinja2Templates(directory=templates_dir)


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


def force_authentication(response: Response, auth_realm: str) -> None:
    """
    Force the user to authenticate by setting appropriate headers and
    status codes on ``response``

    Args:
        response: The response object
        auth_realm: The value to use for the "realm" setting of the
            ``WWW-Authenticate`` header
    """
    response.headers["WWW-Authenticate"] = f'Basic realm="{auth_realm}"'
    response.headers["Cache-Control"] = "no-cache"
    response.status_code = status.HTTP_401_UNAUTHORIZED


@app.get("/auth/login", response_class=HTMLResponse, name="login")
async def login(request: Request, service: str = "/"):
    """
    If the user is already logged in, redirect to target URI, given by the
    ``X-Target-URI`` header.  Otherwise, display the login form.

    If the header ``X-Auth-Realm`` is set, use that as the title for the login
    page.  Otherwise use
    :py:attr:`nginx_ldap_auth.settings.Settings.auth_realm`.

    Args:
        request: The request object

    Keyword Args:
        service: redirect the user to this URL after successful login
    """
    auth_realm = request.headers.get("x-auth-realm", settings.auth_realm)
    logger.info("auth.login.start", target=service, realm=auth_realm, headers=request.headers)
    await load_session(request)
    if request.session.get("username"):
        session_id = get_session_handler(request).session_id
        logger.info(
            "auth.login.success.already_logged_in",
            username=request.session["username"],
            session_id=session_id,
            target=service,
        )
        return RedirectResponse(url=service)
    return templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            "site_title": auth_realm,
            "service": service
        }
    )


@app.post("/auth/login", response_class=HTMLResponse, name="login_handler")
async def login_handler(request: Request):
    """
    Process our user's login request.  If authentication is successful,
    redirect to the target URI, given by the ``X-Target-URI`` header.

    If authentication fails, display the login form again.

    If the header ``X-Auth-Realm`` is set, use that as the title for the login
    page.  Otherwise use
    :py:attr:`nginx_ldap_auth.settings.Settings.auth_realm`.

    Args:
        request: The request object
    """
    auth_realm = request.headers.get("x-auth-realm", settings.auth_realm)
    form = LoginForm(request)
    form.site_title = auth_realm
    await form.load_data()
    if await form.is_valid():
        await load_session(request)
        request.session["username"] = form.username
        return RedirectResponse(url=form.service, status_code=status.HTTP_302_FOUND)
    else:
        return templates.TemplateResponse("login.html", form.__dict__)


@app.get("/auth/logout", response_class=HTMLResponse, name="logout")
async def logout(request: Request):
    """
    Log the user out and redirect to the login page.

    Args:
        request: The request object
    """
    await load_session(request)
    if username := request.session.get("username"):
        await kill_session(request)
        logger.info("auth.logout", username=username)
    return RedirectResponse(url='/auth/login?service=/')


@app.get("/check")
async def index(request: Request, response: Response):
    """
    Ensure the user is still authorized.  If the user is authorized, return
    200 OK, otherwise return 401 Unauthorized.

    The user is authorized if the cookie exists, the session the cookie refers
    to exists, and the ``username`` key in the settings is set.

    Args:
        request: The request object
        response: The response object
    """
    if request.cookies.get(settings.cookie_name):
        await load_session(request)
        if request.session.get("username"):
            # We have a valid session
            return {}
        else:
            # Destroy the session because it is not valid
            await kill_session(request)
    # Force the user to authenticate
    response.headers["Cache-Control"] = "no-cache"
    response.status_code = status.HTTP_401_UNAUTHORIZED
    return {}
