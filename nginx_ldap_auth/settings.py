from typing import Literal

from pydantic import RedisDsn, ValidationError, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from nginx_ldap_auth.validators import validate_ldap_search_filter


class Settings(BaseSettings):
    """
    Settings for the nginx_ldap_auth service.
    """

    # ==================
    # Logging
    # ==================

    #: FastAPI debug mode
    debug: bool = False
    #: Default log level.  Choose from any of the standard Python log levels.
    loglevel: Literal["NOTSET", "DEBUG", "INFO", "WARN", "ERROR", "CRITICAL"] = "INFO"
    #: What format should we log in?  Valid values are ``json`` and ``text``
    log_type: Literal["json", "text"] = "text"

    # ==================
    # HTTP
    # ==================

    #: Use this as the title for the login form, to give a hint to the
    #: user as to what they're logging into
    auth_realm: str = "Restricted"

    #: Whether to run the web server without TLS
    insecure: bool = False

    # ==================
    # Session
    # ==================

    #: The name of the cookie to set when a user authenticates
    cookie_name: str = "nginxauth"
    #: The domain to use for our session cookie, if any.
    cookie_domain: str | None = None
    #: The secret key to use for session cookies
    secret_key: str
    #: The maximum age of a session cookie in seconds
    session_max_age: int = 0
    #: Reset the session lifetime to :py:attr:`session_max_age` every time the
    #: user accesses the protected site
    use_rolling_session: bool = False
    #: Session type: either ``redis`` or ``memory``
    session_backend: Literal["redis", "memory"] = "memory"
    #: If using the Redis session backend, the DSN on which to connect to Redis.
    #:
    #: A fully specified Redis DSN looks like this::
    #:
    #:       redis://[username][:password]@host:port/db
    #:
    #: * The username is only necessary if you are using role-based access
    #:   controls on your Redis server.  Otherwise the password is sufficient if you
    #:   have a server password for your Redis server.
    #: * If you don't specify a database, ``0`` is used.
    #: * If you don't specify a password, no password is used.
    #: * If you don't specify a port, ``6379`` is used.
    redis_url: RedisDsn | None = None
    #: If using the Redis session backend, the prefix to use for session keys
    redis_prefix: str = "nginx_ldap_auth."

    # ==================
    # LDAP
    # ==================

    #: The URI via which to connect to LDAP
    ldap_uri: str
    #: The DN as which to bind to LDAP
    ldap_binddn: str
    #: The password to use when binding to LDAP when doing our searches
    ldap_password: str
    #: Whether to use TLS when connecting to LDAP
    ldap_starttls: bool = True
    #: Whether to disable LDAP referrals
    ldap_disable_referrals: bool = False
    #: The base DN under which to perform searches
    ldap_basedn: str
    #: The base DN to append to the user's username when binding.  This is only
    #: important for Active Directory, where we need to use the value of
    #: ``userPrincipalName`` (typically the user's email address) as the
    #: username intead of the dn which would be built as
    #: ``sAMAccountName=user,{LDAP_BASEDN}``.  Include the ``@`` at the begining
    #: of the string.  If this is set, the binddn will be
    #: ``{username}{ldap_user_basedn}``
    ldap_user_basedn: str | None = None
    #: The LDAP attribute to use as the username when searching for a user
    ldap_username_attribute: str = "uid"
    #: The LDAP attribute to use as the full name when getting search results
    ldap_full_name_attribute: str = "cn"
    #: The LDAP search filter to use when searching for a user.  This should
    #: be a valid LDAP search filter.  The search will be a SUBTREE search
    #: with the base DN of :py:attr:`ldap_basedn`.
    #:
    #: You may use these replacement fields in the filter:
    #:
    #: - ``{username_attribute}``: the value of
    #:   :py:class:`Settings.ldap_username_attribute`
    #: - ``{username_full_name_attribute}``: the value of
    #:   :py:class:`Settings.ldap_full_name_attribute`
    #:
    #: The ``{username}`` placeholder must be present in the filter, as it is
    #: used in the search filter as the placeholder for the username supplied by
    #: the user from the login form.
    ldap_get_user_filter: str = "{username_attribute}={username}"
    #: The LDAP search filter to use to determine whether a user is authorized.  This
    #: should a valid LDAP search filter. If this is ``None``, all users who can
    #: successfully authenticate will be authorized.  If this is not ``None``,
    #: the search with this filter must return at least one result for the user
    #: to be authorized.
    #:
    #: You may use these replacement fields in the filter:
    #:
    #: - ``{username_attribute}``: the value of
    #:   :py:attr:`ldap_username_attribute`
    #: - ``{username_full_name_attribute}``: the value of
    #:   :py:attr:`ldap_full_name_attribute`
    #:
    #: The ``{username}`` placeholder must be present in the filter, as it is
    #: used in the search filter as the placeholder for the username supplied by
    #: the user from the login form.
    ldap_authorization_filter: str | None = None
    #: Whether to allow the ``X-Authorization-Filter`` header to override
    #: :py:attr:`ldap_authorization_filter`. When set to ``True`` (the default),
    #: the header value takes precedence over the environment variable setting.
    #:
    #: .. warning::
    #:
    #:    Setting this to ``True`` without properly configuring NGINX to control
    #:    the ``X-Authorization-Filter`` header is a **security risk**. Malicious
    #:    clients could send a permissive filter (e.g., ``(objectClass=*)``) to
    #:    bypass group-based authorization restrictions.
    #:
    #:    For secure deployments, set this to ``False`` and use only the
    #:    :envvar:`LDAP_AUTHORIZATION_FILTER` environment variable, or ensure your
    #:    NGINX configuration explicitly sets or clears the header using
    #:    ``proxy_set_header`` before forwarding requests.
    #:
    #: .. note::
    #:
    #:    The default is ``True`` for backwards compatibility. Future versions
    #:    may change the default to ``False`` for improved security.
    allow_authorization_filter_header: bool = True
    #: Number of seconds to wait for an LDAP connection to be established
    ldap_timeout: int = 15
    #: Min number of LDAP connections to keep in the pool
    ldap_min_pool_size: int = 1
    #: Max number of LDAP connections to keep in the pool
    ldap_max_pool_size: int = 30
    #: Recycle LDAP connections after this many seconds
    ldap_pool_connection_lifetime_seconds: int = 20

    # ==================
    # Duo
    # ==================
    #: Whether to enable Duo MFA
    duo_enabled: bool = False
    #: Duo integration host
    duo_host: str | None = None
    #: Duo integration ikey
    duo_ikey: str | None = None
    #: Duo integration skey
    duo_skey: str | None = None

    # ==================
    # Sentry
    # ==================
    #: The sentry DSN to use for error reporting.  If this is ``None``, no
    #: error reporting will be done.
    sentry_url: str | None = None

    model_config = SettingsConfigDict()

    @model_validator(mode="after")  #: type: ignore
    def redis_url_required_if_session_type_is_redis(self):
        """
        If we've configured the session backend to be ``redis``,
        :py:attr:`redis_url` is required.

        Raises:
            ValidationError: ``redis_url`` is required if ``session_backend`` is
            ``redis``

        """
        if self.session_backend == "redis" and not self.redis_url:
            msg = "redis_url is required if session_backend is redis"
            raise ValidationError(msg)
        return self

    @model_validator(mode="after")  #: type: ignore
    def duo_settings_required_if_enabled(self):
        """
        If we've enabled Duo MFA, :py:attr:`duo_host`, :py:attr:`duo_ikey`,
        and :py:attr:`duo_skey` are required.

        Raises:
            ValidationError: Duo settings are required if ``duo_enabled`` is
            ``True``

        """
        if self.duo_enabled:
            if not all([self.duo_host, self.duo_ikey, self.duo_skey]):
                msg = (
                    "duo_host, duo_ikey, and duo_skey are required if duo_enabled "
                    "is True"
                )
                raise ValidationError(msg)
        return self

    @model_validator(mode="after")  #: type: ignore
    def ensure_authorization_filter_header_is_a_valid_ldap_filter(self):
        """
        Ensure that the authorization filter is a valid LDAP filter.

        Raises:
            ValueError: The authorization filter is not a valid LDAP filter
            ValueError: The authorization filter does not use the {username} placeholder

        """
        if self.allow_authorization_filter_header and self.ldap_authorization_filter:
            validate_ldap_search_filter(
                self.ldap_authorization_filter,
                ldap_username_attribute=self.ldap_username_attribute,
                ldap_full_name_attribute=self.ldap_full_name_attribute,
            )
        return self

    @model_validator(mode="after")  #: type: ignore
    def ensure_get_user_filter_is_a_valid_ldap_filter(self):
        """
        Ensure that the get user filter is a valid LDAP filter.

        Raises:
            ValueError: The get user filter is not a valid LDAP filter
            ValueError: The get user filter does not use the {username} placeholder

        """
        validate_ldap_search_filter(
            self.ldap_get_user_filter,
            ldap_username_attribute=self.ldap_username_attribute,
            ldap_full_name_attribute=self.ldap_full_name_attribute,
        )
        return self
