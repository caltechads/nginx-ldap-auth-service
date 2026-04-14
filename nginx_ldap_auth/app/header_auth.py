"""
Header-based authorization endpoint for Kerberos/SPNEGO authentication.

This module provides a stateless authorization endpoint that accepts user
identity from a trusted header (set by NGINX after Kerberos authentication)
and checks LDAP group membership for authorization.
"""

from typing import Any

from bonsai import LDAPError
from fastapi import APIRouter, Request, Response, status

from nginx_ldap_auth.settings import Settings

from ..logging import get_logger
from .header_auth_cache import (
    authorization_lock,
    get_cached_authorization,
    set_cached_authorization,
)
from .models import User

router = APIRouter(tags=["header-auth"])

settings = Settings()


@router.get("/check-header")
async def check_header_auth(  # noqa: PLR0911
    request: Request, response: Response
) -> dict[str, Any]:
    """
    Stateless authorization check for header-based authentication.

    This endpoint is designed for use with Kerberos/SPNEGO authentication
    where NGINX handles authentication and passes the username via a
    trusted header (default: ``X-Ldap-User``).

    **Response Codes:**

    - ``200 OK``: User is authorized
    - ``401 Unauthorized``: Missing username header
    - ``403 Forbidden``: User is not authorized (not in required group)
    - ``500 Internal Server Error``: LDAP error
    """
    _logger = get_logger(request)
    response.headers["Cache-Control"] = "no-cache"

    # Get username from trusted header
    header_name = settings.ldap_trusted_user_header
    username = request.headers.get(header_name.lower())
    is_authorized = False

    if not username:
        _logger.warning("header_auth.check.missing_header", header=header_name)
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return {}

    # Get authorization filter from header or settings
    if settings.allow_authorization_filter_header:
        ldap_authorization_filter = request.headers.get(
            "x-authorization-filter", settings.ldap_authorization_filter
        )
    else:
        ldap_authorization_filter = settings.ldap_authorization_filter

    if not ldap_authorization_filter or not ldap_authorization_filter.strip():
        _logger.error(
            "header_auth.check.missing_authorization_filter",
            username=username,
            allow_authorization_filter_header=settings.allow_authorization_filter_header,
            header_present="x-authorization-filter" in request.headers,
            settings_filter_present=bool(settings.ldap_authorization_filter),
        )
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        return {}

    # Use distributed lock to prevent thundering herd on LDAP
    async with authorization_lock(username, ldap_authorization_filter):
        # Check cache (inside lock to prevent duplicate LDAP queries)
        cached_result = await get_cached_authorization(
            username, ldap_authorization_filter
        )

        if cached_result is not None:
            if cached_result:
                _logger.info("header_auth.check.success.cached", username=username)
                response.headers["X-Auth-User"] = username
                return {}
            _logger.info("header_auth.check.forbidden.cached", username=username)
            response.status_code = status.HTTP_403_FORBIDDEN
            return {}

        # Cache miss - query LDAP
        try:
            is_authorized = await User.objects.is_authorized(
                username, ldap_authorization_filter
            )
        except LDAPError:
            _logger.exception("header_auth.check.ldap_error", username=username)
            response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            return {}

        # Cache the result
        await set_cached_authorization(
            username, ldap_authorization_filter, authorized=is_authorized
        )

    # Return result (outside lock)
    if is_authorized:
        _logger.info("header_auth.check.success", username=username)
        response.headers["X-Auth-User"] = username
        return {}
    _logger.info(
        "header_auth.check.forbidden",
        username=username,
        filter=ldap_authorization_filter,
    )
    response.status_code = status.HTTP_403_FORBIDDEN
    return {}
