from typing import Optional

from pydantic import BaseSettings


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
    #: The name of the cookie to set when a user authenticates
    cookie_name: str = 'nginxauth'

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
    #: The base DN to search for users under
    ldap_username_attribute: str = 'uid'
    #: The base DN to search for users under
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

    class Config:
        fields = {
            'debug': {'env': 'DEBUG'},
            'hostname': {'env': 'HOSTNAME'},
            'port': {'env': 'PORT'},
            'auth_realm': {'env': 'AUTH_REALM'},
            'cookie_name': {'env': 'COOKIE_NAME'},
            'ldap_uri': {'env': 'LDAP_URI'},
            'ldap_starttls': {'env': 'LDAP_STARTTLS'},
            'ldap_disable_referrals': {'env': 'LDAP_DISABLE_REFERRALS'},
            'ldap_binddn': {'env': 'LDAP_BINDDN'},
            'ldap_password': {'env': 'LDAP_PASSWORD'},
            'ldap_timeout': {'env': 'LDAP_TIMEOUT'},
            'ldap_min_pool_size': {'env': 'LDAP_MIN_POOL_SIZE'},
            'ldap_max_pool_size': {'env': 'LDAP_MAX_POOL_SIZE'},
            'ldap_pool_connection_lifetime_seconds': {'env': 'LDAP_POOL_CONNECTION_LIFETIME_SECONDS'},
            'ldap_filter': {'env': 'LDAP_FILTER'},
            'statsd_host': {'env': 'STATSD_HOST'},
            'statsd_port': {'env': 'STATSD_PORT'},
            'statsd_prefix': {'env': 'STATSD_PREFIX'},
            'sentry_url': {'env': 'SENTRY_URL'},
        }
