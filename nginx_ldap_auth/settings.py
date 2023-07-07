from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict
try:
    from typing import Literal
except ImportError:
    from typing_extensions import Literal


class Settings(BaseSettings):

    debug: bool = False

    #: The hostname to bind to
    hostname: str = 'localhost'
    #: The port to answer on
    port: int = 8888

    # HTTP
    #: Declare this authentication realm to the user when asking them to
    #: authenticate
    auth_realm: str = 'Restricted'

    # Session
    #: The name of the cookie to set when a user authenticates
    cookie_name: str = 'nginxauth'
    #: The secret key to use for session cookies
    secret_key: str = 'SESSION_SECRET'
    #: The maximum age of a session cookie in seconds
    session_max_age: int = 0
    #: session type
    session_backend: Literal['redis', 'memory'] = 'memory'
    #: If using the Redis session backend, the URL to connect to Redis on
    redis_url: str = 'redis://localhost'
    #: If using the Redis session backend, the prefix to use for session keys
    redis_prefix: str = "nginx_ldap_auth."

    # LDAP
    #: The URI to connect to LDAP on
    ldap_uri: Optional[str] = None
    #: The DN to bind to LDAP as
    ldap_binddn: Optional[str] = None
    #: Whether to use TLS when connecting to LDAP
    ldap_starttls: bool = True
    #: Whether to disable LDAP referrals
    ldap_disable_referrals: bool = False
    #: The password to use when binding to LDAP
    ldap_password: Optional[str] = None
    #: The base DN to search for users under
    ldap_basedn: str = 'ou=users,dc=example,dc=com'
    #: The attribute to use as the username when searching for a user
    ldap_username_attribute: str = 'uid'
    #: The attribute to use as the full name when getting search results
    ldap_full_name_attribute: str = 'cn'
    #: The LDAP search filter to use when searching for a user
    ldap_filter: str = '{username_attribute}={username}'
    #: Number of seconds to wait for an LDAP connection
    ldap_timeout: int = 15
    #: Min number of LDAP connections to keep in the pool
    ldap_min_pool_size: int = 1
    #: Max number of LDAP connections to keep in the pool
    ldap_max_pool_size: int = 30
    #: Recycle LDAP connections after this many seconds
    ldap_pool_connection_lifetime_seconds: int = 20

    # Monitoring
    statsd_host: Optional[str] = None
    statsd_port: int = 8125
    statsd_prefix: str = 'nginx_ldap_auth.dev'

    # Sentry
    sentry_url: Optional[str] = None

    model_config = SettingsConfigDict()
