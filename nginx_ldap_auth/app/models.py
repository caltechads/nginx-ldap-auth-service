from typing import ClassVar, Optional, cast

import bonsai
from bonsai.errors import (
    AuthenticationError,
    LDAPError,
)
from bonsai.utils import escape_filter_exp
from pydantic import BaseModel

from nginx_ldap_auth.ldap import (
    TimeLimitedAIOConnectionPool,
    TimeLimitedAIOLDAPConnection,
)
from nginx_ldap_auth.logging import logger
from nginx_ldap_auth.settings import Settings
from nginx_ldap_auth.types import LDAPObject


class UserManager:
    """
    Manage users in the LDAP directory.
    """

    #: The model class for users
    model: ClassVar[type["User"]]

    def __init__(self) -> None:
        #: The application settings
        self.settings = Settings()
        #: The LDAP connection pool
        self.pool: TimeLimitedAIOConnectionPool | None = None

    def client(self) -> bonsai.LDAPClient:
        """
        Return a new LDAP client instance.

        If :py:attr:`nginx_ldap_auth.settings.Settings.ldap_starttls` is ``True``,
        the client will be configured to use TLS.
        """
        client = bonsai.LDAPClient(
            cast(str, self.settings.ldap_uri), tls=self.settings.ldap_starttls
        )
        client.set_cert_policy("never")
        client.set_ca_cert(None)
        client.set_ca_cert_dir(None)
        client.ignore_referrals = self.settings.ldap_disable_referrals
        client.set_server_chase_referrals(not self.settings.ldap_disable_referrals)
        client.set_async_connection_class(TimeLimitedAIOLDAPConnection)
        return client

    async def create_pool(self) -> None:
        """
        Create the LDAP connection pool and save it as :py:attr:`pool`.
        """
        client = self.client()
        if self.settings.ldap_binddn and self.settings.ldap_password:
            client.set_credentials(
                "SIMPLE",
                user=self.settings.ldap_binddn,
                password=self.settings.ldap_password,
            )
        self.pool = TimeLimitedAIOConnectionPool(
            self.settings,
            client,
            minconn=self.settings.ldap_min_pool_size,
            maxconn=self.settings.ldap_max_pool_size,
            expires=self.settings.ldap_pool_connection_lifetime_seconds,
        )
        await self.pool.open()

    async def authenticate(self, username: str, password: str) -> bool:
        """
        Authenticate a user against the LDAP server.

        If :py:attr:`nginx_ldap_auth.settings.Settings.ldap_user_basedn` is set,
        we will prepend the username with that value to create the DN to bind
        with like so: "{username}{ldap_user_base_dn}.  Otherwise, we will use
        the value of
        :py:attr:`nginx_ldap_auth.settings.Settings.ldap_username_attribute` to
        create the DN as ``{username_attribute}={username},{ldap_basedn}``.

        Args:
            username: the username to authenticate
            password: the password to authenticate with

        Raises:
            LDAPError: if an error occurs while communicating with the LDAP server

        Returns:
            ``True`` if the user is authenticated, ``False`` otherwise

        """
        if self.settings.ldap_user_basedn:
            # This is AD and we need to use the userPrincipalName
            dn = f"{username}{self.settings.ldap_user_basedn}"
        else:
            dn = (
                f"{self.settings.ldap_username_attribute}={username},"
                f"{self.settings.ldap_basedn}"
            )
        client = self.client()
        client.set_credentials("SIMPLE", user=dn, password=password)
        logger.info(
            "ldap.authenticate",
            dn=dn,
            uri=self.settings.ldap_uri,
        )
        try:
            await client.connect(is_async=True)
        except AuthenticationError as e:
            logger.error(
                "ldap.authenticate.error.invalid_credentials",
                dn=dn,
                uri=self.settings.ldap_uri,
                exc_info=str(e),
            )
            return False
        except LDAPError:
            logger.exception("ldap.authenticate.exception", uid=username)
            raise
        return True

    async def exists(self, username: str) -> bool:
        """
        Return ``True`` if the user exists in the LDAP directory, ``False``
        otherwise.

        Args:
            username: the username to check

        Raises:
            LDAPError: if an error occurred while communicating with the LDAP server
            AuthenticationError: if the LDAP server rejects the credentials of
                :py:class:`nginx_ldap_auth.settings.Settings.ldap_binddn` and
                :py:class:`nginx_ldap_auth.settings.Settings.ldap_password`

        Returns:
            ``True`` if the user exists in the LDAP directory, ``False``
            otherwise

        """
        return await self.get(username) is not None

    async def is_authorized(self, username: str) -> bool:
        """
        Test whether the user is authorized to log in.  This is done by
        performing an LDAP search using the filter specified in
        :py:class:`nginx_ldap_auth.settings.Settings.ldap_authorization_filter`.
        If that setting is ``None``, the user is considered authorized.

        Args:
            username: the username to check

        Raises:
            LDAPError: if an error occurred while communicating with the LDAP server
            AuthenticationError: if the LDAP server rejects the credentials of
                :py:class:`nginx_ldap_auth.settings.Settings.ldap_binddn` and
                :py:class:`nginx_ldap_auth.settings.Settings.ldap_password`

        Returns:
            ``True`` if the user is authorized to log in, ``False`` otherwise.

        """
        if not self.pool:
            await self.create_pool()
        pool = cast(TimeLimitedAIOConnectionPool, self.pool)
        if self.settings.ldap_authorization_filter is None:
            return True
        try:
            async with pool.spawn() as conn:
                results = await conn.search(
                    base=self.settings.ldap_basedn,
                    scope=bonsai.LDAPSearchScope.SUBTREE,
                    filter_exp=self.settings.ldap_authorization_filter.format(
                        username_attribute=self.settings.ldap_username_attribute,
                        fullname_attribute=self.settings.ldap_full_name_attribute,
                        username=escape_filter_exp(username),
                    ),
                    attrlist=[self.settings.ldap_username_attribute],
                )
        except AuthenticationError:
            logger.error(
                "ldap.is_authorized.error.invalid_credentials",
                bind_dn=self.settings.ldap_binddn,
            )
            raise
        except LDAPError:
            logger.exception(
                "ldap.is_authorized.exception",
                bind_dn=self.settings.ldap_binddn,
                username=username,
            )
            raise
        return len(results) > 0

    async def get(self, username: str) -> Optional["User"]:
        """
        Get a user from the LDAP directory, and return it as a :py:class:`User`.
        When getting the user, we will use the LDAP search filter specified in
        :py:class:`nginx_ldap_auth.settings.Settings.ldap_get_user_filter`.

        Args:
            username: the username for which to get user information

        Raises:
            LDAPError: if an error occurred while communicating with the LDAP server
            AuthenticationError: if the LDAP server rejects the credentials of
                :py:class:`nginx_ldap_auth.settings.Settings.ldap_binddn` and
                :py:class:`nginx_ldap_auth.settings.Settings.ldap_password`

        Returns:
            The user information as a :py:class:`User` instance, or ``None`` if
            the user is not returned by the LDAP search filter

        """
        if not self.pool:
            await self.create_pool()
        pool = cast(TimeLimitedAIOConnectionPool, self.pool)
        try:
            async with pool.spawn() as conn:
                results = await conn.search(
                    base=self.settings.ldap_basedn,
                    scope=bonsai.LDAPSearchScope.SUBTREE,
                    filter_exp=self.settings.ldap_get_user_filter.format(
                        username_attribute=self.settings.ldap_username_attribute,
                        fullname_attribute=self.settings.ldap_full_name_attribute,
                        username=escape_filter_exp(username),
                    ),
                    attrlist=[
                        self.settings.ldap_username_attribute,
                        self.settings.ldap_full_name_attribute,
                    ],
                )
        except AuthenticationError:
            logger.error(
                "ldap.get_user.error.invalid_credentials",
                bind_dn=self.settings.ldap_binddn,
            )
            raise
        except LDAPError:
            logger.exception(
                "ldap.get_user.exception",
                bind_dn=self.settings.ldap_binddn,
                username=username,
            )
            raise
        if results:
            if len(results) > 1:
                logger.warning(
                    "ldap.get_user.error.multiple_results",
                    bind_dn=self.settings.ldap_binddn,
                    username=username,
                    dns=";".join([r[0] for r in results]),
                )
            return self.model.parse_ldap(results[0])
        return None

    async def cleanup(self) -> None:
        """
        Close the LDAP connection pool.
        """
        if self.pool:
            await self.pool.close()


class User(BaseModel):
    """
    Used to represent a user in the LDAP directory.  It is constructed from the
    LDAP response, and is used to authenticate the user against the LDAP server.
    """

    objects: ClassVar["UserManager"] = UserManager()

    #: The username of the user.
    uid: str
    #: The full name of the user.  We really only use this for logging.
    full_name: str

    async def authenticate(self, password: str) -> bool:
        """
        Authenticate this user against the LDAP server.

        Args:
            password: the password to authenticate with

        Returns:
            ``True`` if the user is authenticated, ``False`` otherwise

        """
        return await self.objects.authenticate(self.uid, password)

    @classmethod
    def parse_ldap(cls, data: LDAPObject) -> "User":
        """
        Parse the LDAP response, and extract the uid and full name from
        the LDAP server to use in constructing this class.

        We use
        :py:attr:`nginx_ldap_auth.settings.Settings.ldap_username_attribute` to
        determine which LDAP attribute on ``data`` holds our :py:attr:`uid` value, and
        :py:attr:`nginx_ldap_auth.settings.Settings.ldap_full_name_attribute` to
        determine which LDAP attribute holds our :py:attr:`full_name` value.

        Args:
            data: the raw LDAP data

        Returns:
            A configured :py:class:`User` object

        """
        settings = Settings()
        username_attribute = settings.ldap_username_attribute
        fullname_attribute = settings.ldap_full_name_attribute
        kwargs = {
            "uid": data[username_attribute][0],
            "full_name": data[fullname_attribute][0],
        }
        logger.info("user.parse_ldap", **kwargs)
        return cls(**kwargs)


UserManager.model = User
