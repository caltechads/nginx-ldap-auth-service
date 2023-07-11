from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict
try:
    from typing import Literal
except ImportError:
    from typing_extensions import Literal  # type: ignore


class Settings(BaseSettings):

    # ==================
    # Logging
    # ==================

    #: FastAPI debug mode
    debug: bool = False
    #: Default log level.  Choose from any of the standard Python log levels.
    loglevel: Literal['NOTSET', 'DEBUG', 'INFO', 'WARN', 'ERROR', 'CRITICAL'] = 'INFO'
    #: What format should we log in?  Valid values are ``json`` and ``text``
    log_type: Literal['json', 'text'] = 'text'

    # ==================
    # HTTP
    # ==================

    #: Use this as the title for the login form, to give a hint to the
    #: user as to what they're logging into
    auth_realm: str = 'Restricted'

    # ==================
    # Session
    # ==================

    #: The name of the cookie to set when a user authenticates
    cookie_name: str = 'nginxauth'
    #: The domain to use for our session cookie, if any.
    cookie_domain: Optional[str] = None
    #: The secret key to use for session cookies
    secret_key: str = 'SESSION_SECRET'
    #: The maximum age of a session cookie in seconds
    session_max_age: int = 0
    #: Session type: either ``redis`` or ``memory``
    session_backend: Literal['redis', 'memory'] = 'memory'
    #: If using the Redis session backend, the URL to connect to Redis on
    redis_url: str = 'redis://localhost'
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
    ldap_basedn: str = 'ou=users,dc=example,dc=com'
    #: The LDAP attribute to use as the username when searching for a user
    ldap_username_attribute: str = 'uid'
    #: The LDAP attribute to use as the full name when getting search results
    ldap_full_name_attribute: str = 'cn'
    #: The LDAP search filter to use when searching for a user.  This should
    #: be a valid LDAP search filter.  The search will be a SUBTREE search
    #: with the base DN of :py:attr:`ldap_basedn`.
    #:
    #: You may use these replacement fields in the filter:
    #:
    #: - ``{username_attribute}``: the value of :py:class:`Settings.ldap_username_attribute`
    #: - ``{username_full_name_attribute}``: the value of :py:class:`Settings.ldap_full_name_attribute`
    #:
    #: Use ``{username}`` in the search filter as the placeholder for the username
    #: supplied by the user from the login form.
    ldap_get_user_filter: str = '{username_attribute}={username}'
    #: The LDAP search filter to use to determine whether a user is authorized.  This
    #: should a valid LDAP search filter. If this is ``None``, all users who can successfully
    #: authenticate will be authorized.  If this is not ``None``, the search with this
    #: filter must return at least one result for the user to be authorized.
    #:
    #: You may use these replacement fields in the filter:
    #:
    #: - ``{username_attribute}``: the value of :py:attr:`ldap_username_attribute`
    #: - ``{username_full_name_attribute}``: the value of :py:attr:`ldap_full_name_attribute`
    #:
    #: Use ``{username}`` in the search filter as the placeholder for the username
    #: supplied by the user from the login form.
    ldap_authorization_filter: Optional[str] = None
    #: Number of seconds to wait for an LDAP connection to be established
    ldap_timeout: int = 15
    #: Min number of LDAP connections to keep in the pool
    ldap_min_pool_size: int = 1
    #: Max number of LDAP connections to keep in the pool
    ldap_max_pool_size: int = 30
    #: Recycle LDAP connections after this many seconds
    ldap_pool_connection_lifetime_seconds: int = 20

    # ==================
    # Sentry
    # ==================
    #: The sentry DSN to use for error reporting.  If this is ``None``, no
    #: error reporting will be done.
    sentry_url: Optional[str] = None

    model_config = SettingsConfigDict()
