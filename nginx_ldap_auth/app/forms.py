from typing import List, cast
from typing import Optional

from fastapi import Request

from ..logging import logger
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
        If the form username and password are valid, return ``True``.
        Otherwise, return ``False``.

        To be valid, the username must not be empty, and a user with the
        provided username must exist in the LDAP directory. The password must
        not be empty, and the password must be valid for the user in the LDAP
        directory.

        Returns:
            ``True`` if the form is valid, ``False`` otherwise.
        """
        if not self.username:
            logger.info("auth.failed.username")
            self.errors.append("Username is required")
        if not self.password:
            logger.info("auth.failed.no_password")
            self.errors.append("A valid password is required")
        if user := await User.objects.get(cast(str, self.username)):
            # The user exists in LDAP
            user = cast(User, user)
            if await user.authenticate(cast(str, self.password)):
                # The user has provided valid credentials
                logger.info(
                    "auth.success",
                    username=self.username,
                    full_name=user.full_name,
                    ldap_url=settings.ldap_uri,
                    target=self.service,
                    realm=self.site_title
                )
            else:
                self.errors.append("Invalid username or password.")
                logger.info(
                    "auth.failed.invalid_credentials",
                    username=self.username,
                    target=self.service,
                    realm=self.site_title
                )
        else:
            self.errors.append("Invalid username or password.")
            logger.warning(
                "auth.failed.no_such_user",
                username=self.username,
                target=self.service,
                realm=self.site_title
            )
        if not self.errors:
            return True
        return False
