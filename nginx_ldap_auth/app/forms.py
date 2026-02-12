from typing import cast

from fastapi import Request

from ..logging import get_logger
from ..settings import Settings
from .models import User

settings = Settings()


class LoginForm:
    """
    The form class for the login form.
    """

    def __init__(self, request: Request) -> None:
        #: The current request object
        self.request: Request = request
        #: The errors to display to the user
        self.errors: list = []
        #: The username to authenticate
        self.username: str | None = None
        #: The password to authenticate
        self.password: str | None = None
        #: The service to redirect to after authentication
        self.service: str = "/"
        #: The title of the site
        self.site_title: str = settings.auth_realm

    async def load_data(self) -> None:
        """
        Load data from request form.
        """
        form = await self.request.form()
        self.username = cast("str", form.get("username"))
        self.password = cast("str", form.get("password"))
        self.service = cast("str", form.get("service", "/"))

    async def is_valid(self) -> bool:
        """
        Return whether the form is valid.

        * the form must have a non-empty username and password
        * the user must exist in LDAP meaning that the user must be in the
          results of the ldap search
          named by :py:attr:`nginx_ldap_auth.settings.Settings.ldap_get_user_filter`
        * If the ``X-Authorization-Filter`` header (when
          :py:attr:`nginx_ldap_auth.settings.Settings.allow_authorization_filter_header`
          is ``True``) or
          :py:attr:`nginx_ldap_auth.settings.Settings.ldap_authorization_filter`
          is not ``None``, the user must be in the results of that LDAP search.
          The optional header will override the setting when allowed.
        * the bind to LDAP must be successful

        If all those tests pass, return ``True``.  Otherwise, return ``False``.

        Returns:
            ``True`` if the form is valid, ``False`` otherwise.

        """
        _logger = get_logger(self.request)
        if not self.username:
            _logger.info("auth.failed.no_username")
            self.errors.append("Username is required")
        if not self.password:
            _logger.info("auth.failed.no_password")
            self.errors.append("A valid password is required")
        if user := await User.objects.get(cast("str", self.username)):
            # The user exists in LDAP
            user = cast("User", user)
            # Ensure that the user is authorized to access this service
            if settings.allow_authorization_filter_header:
                ldap_authorization_filter: str | None = self.request.headers.get(
                    "x-authorization-filter", settings.ldap_authorization_filter
                )
            else:
                ldap_authorization_filter = settings.ldap_authorization_filter
            if not await User.objects.is_authorized(
                cast("str", self.username), ldap_authorization_filter
            ):
                self.errors.append("You are not authorized to access this service.")
                _logger.warning(
                    "auth.failed.not_authorized",
                    username=self.username,
                    full_name=user.full_name,
                    ldap_url=settings.ldap_uri,
                    target=self.service,
                )
            # Now try to authenticate the user
            if await user.authenticate(cast("str", self.password)):
                # The user has provided valid credentials
                _logger.info(
                    "auth.success",
                    username=self.username,
                    full_name=user.full_name,
                    ldap_url=settings.ldap_uri,
                    target=self.service,
                )
            else:
                self.errors.append("Invalid username or password.")
                _logger.info(
                    "auth.failed.invalid_credentials",
                    username=self.username,
                    target=self.service,
                )
        else:
            self.errors.append("Invalid username or password.")
            _logger.warning(
                "auth.failed.no_such_user",
                username=self.username,
                target=self.service,
            )
        return bool(not self.errors)
