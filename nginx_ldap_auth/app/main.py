#!/usr/bin/env python
# -*- coding: utf-8 -*-

import base64
from typing import Annotated, Optional, cast
from fastapi import Cookie, FastAPI, Header, Request, Response, status

from nginx_ldap_auth import __version__
from nginx_ldap_auth.settings import Settings
from nginx_ldap_auth.logging import logger

from .models import User


settings = Settings()

app = FastAPI(
    title="nginx_ldap_auth",
    debug=settings.debug,
    version=__version__
)


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


@app.get("/")
async def index(
    request: Request,
    response: Response,
    authorization: Annotated[Optional[str], Header()] = None,
    auth_realm: Annotated[Optional[str], Header(name="X-Auth-Realm")] = None,
    cookie_name: Annotated[Optional[str], Header(name="X-Cookie-Name")] = None,
):
    """
    Ensure the user is still authorized.

    First look at the ``Authorization`` header for credentials. If that's not
    present, look at the cookie named by the ``X-Cookie-Name`` header for the
    credentials.  If that header is not present, use the value of
    :py:attr:`nginx_ldap_auth.settings.Settings.cookie_name` instead.

    Use those credentials to look up the user in LDAP. If the user exists, bind
    as them to verify their password. If the password is correct, return ``200
    OK``

    Otherwise return ``401 Unauthorized`` and force the user to authenticate by
    setting the ``WWW-Authenticate`` header.

    Args:
        request: The request object
        response: The response object

    Keyword Args:
        authorization: The value of the ``Authorization`` header
        cookie_name: The name of the cookie to look at for credentials
    """
    if not cookie_name:
        cookie_name = settings.cookie_name
    if not auth_realm:
        auth_realm = settings.auth_realm
    if cookie := request.cookies.get(cookie_name):
        # The user has already authenticated
        authorization = f"Basic {cookie}"
        logger.info("auth.start.cookie_found")
    if not authorization or not authorization.lower().startswith("basic "):
        # This is the first time we've seen the user
        force_authentication(response, auth_realm)
        return {}

    try:
        # The credentials will be in the format "Basic <base64-encoded username:password>"
        credentials = authorization.split(" ", 1)[1]
        username, password = base64.b64decode(credentials).decode('utf-8').split(":", 1)
    except (IndexError, UnicodeDecodeError, ValueError):
        # The credentials are invalid
        logger.exeption("auth.failed.credentials.parse_error")
        force_authentication(response)
        return {}

    if not password:
        # The user didn't provide a password
        logger.info("auth.failed.no_password")
        force_authentication(response)
        return {}

    if user := await User.objects.get(username):
        # The user exists in LDAP
        user = cast(User, user)
        if await user.authenticate(password):
            # The user has provided valid credentials
            logger.info(
                "auth.success",
                username=username,
                full_name=user.full_name,
                ldap_url=settings.ldap_uri
            )
        else:
            # The user has provided invalid credentials
            logger.info("auth.failed.invalid_credentials", username=username)
            force_authentication(response)
    else:
        # The user doesn't exist in LDAP
        logger.info("auth.failed.user_not_found", username=username)
        force_authentication(response)
    return {}
