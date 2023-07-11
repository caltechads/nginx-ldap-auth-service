from typing import List, cast
from typing import Optional

from fastapi import Request

from ..logging import get_logger
from ..settings import Settings
from .models import User

settings = Settings()


class LoginForm:
    """
    The form class for the login form.
    """

    def __init__(self, request: Request):
        self.request: Request = request
        self.errors: List = []
        self.username: Optional[str] = None
        self.password: Optional[str] = None
        self.service: str = "/"
        self.site_title: str = settings.auth_realm

    async def load_data(self) -> None:
        """
        Load data from request form.
        """
        form = await self.request.form()
        self.username = cast(Optional[str], form.get("username"))
        self.password = cast(Optional[str], form.get("password"))
        self.service = cast(str, form.get("service", "/"))

    async def is_valid(self) -> bool:
        """
        Return whether the form is valid.

        * the form must have a non-empty username and password
        * the user must exist in LDAP and must pass the authorization test,
          meaning that the user must be in the results of the ldap search
          named by :py:attr:`nginx_ldap_auth.settings.Settings.ldap_filter`
        * the bind to LDAP must be successful

        If all those tests pass, return ``True``.  Otherwise, return ``False``.

        Returns:
            ``True`` if the form is valid, ``False`` otherwise.
        """
        _logger = get_logger(self.request)
        if not self.username:
            _logger.info("auth.failed.username")
            self.errors.append("Username is required")
        if not self.password:
            _logger.info("auth.failed.no_password")
            self.errors.append("A valid password is required")
        if user := await User.objects.get(cast(str, self.username)):
            # The user exists in LDAP
            user = cast(User, user)
            if await user.authenticate(cast(str, self.password)):
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
        if not self.errors:
            return True
        return False
