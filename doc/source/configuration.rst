.. _configuration:

Configuration Overview
======================

.. important::
    This page deals with configuring ``nginx-ldap-auth-service``.  For
    configuring ``nginx`` to use ``nginx-ldap-auth-service``, see :doc:`nginx`.

``nginx-ldap-auth-service`` reads configuration from three places, in
decreasing order of precedence:

#. Command line options for ``nginx-ldap-auth start``
#. Headers set in the location blocks of the ``nginx`` config file
#. Environment variables

Not all configuration options are available in all places.

.. note::

    To print your resolved configuration when using the command line,
    you can run the following command::

        $ nginx-ldap-auth settings

Command Line
------------

If an option is specified on the command line, it overrides all other values
that may have been specified in the app specific environment variables.
configuration file. Not all ``nginx-ldap-auth-service`` settings are available
to be set from the command line. To see the full list of command line settings
you can do the usual::

    $ nginx-ldap-auth start --help

.. _nginx_header_config:

nginx Header Configuration
--------------------------

If an option is specified in the ``nginx`` configuration file, it overrides the
associated setting in ``nginx-ldap-auth-service``.

You can set the following headers in your nginx configuration to configure
``nginx-ldap-auth-service`` on a per ``nginx`` server basis.  You might do this
if you have multiple ``nginx`` servers all using the same
``nginx-ldap-auth-service`` instance, but want to configure them differently.

.. note::

    You can only set the following headers in the ``location`` blocks that
    proxy to ``nginx-ldap-auth-service``.  If you set them in the ``server``
    block, they will be ignored.

CSRF Cookie in the /auth location [required]

    In order for the login page to work, we need to pass the session cookie to
    the auth service.  See :envvar:`CSRF_COOKIE_NAME` for more details on what
    the name of the CSRF cookie will be for you.

    Here's an example of how to set the cookie in the ``/auth`` location:

    Example:

    .. code-block:: nginx
        :emphasize-lines: 4

        location /auth {
            proxy_pass http://nginx-ldap-auth-service:8888/auth;
            proxy_set_header Cookie mycookie_csrf=$cookie_mycookie_csrf;

            # other lines omitted for brevity
        }


X-Cookie-Name

    The name of the session cookie.  Either set this header or set the
    :envvar:`COOKIE_NAME` environment variable.  If ``X-Cookie-Name`` is set, it
    will override the value of :envvar:`COOKIE_NAME`.

    The ``proxy_set_header X-Cookie-Name`` line goes in the ``location`` block
    for the ``/auth`` and ``/check-auth`` locations.

    .. important::

        Whether or not you change the cookie name from its default of ``nginxauth``,
        you'll need the ``proxy_set_header Cookie`` and ``proxy_cache_key`` lines
        below.  Change "mycookie" to whatever you set :envvar:`COOKIE_NAME` to in
        all the places it occurs.

    Example:

    .. code-block:: nginx
        :emphasize-lines: 3,4,19,20,21

        location /auth {
            proxy_pass http://nginx-ldap-auth-service:8888/auth;
            proxy_set_header X-Cookie-Name "mycookie";

            # other lines omitted for brevity
        }

        location /check-auth {
            proxy_pass http://nginx-ldap-auth-service:8888/check;

            # Cache our auth responses for 10 minutes so that we're not
            # hitting the auth service on every request.
            proxy_cache auth_cache;
            proxy_cache_valid 200 10m;

            # other lines omitted for brevity

            proxy_set_header X-Cookie-Name "mycookie";
            proxy_set_header Cookie mycookie=$cookie_mycookie;
            proxy_cache_key "$http_authorization$cookie_mycookie";
        }

    If you're not doing any caching, you can ignore the cache related lines
    above.

X-Cookie-Domain

    The domain for the session cookie.  This goes in the ``location`` block for
    the ``/auth`` and ``/check-auth`` locations.  If you don't specify this
    header, the value of the domain will be that set for :envvar:`COOKIE_DOMAIN`.
    If ``X-Cookie-Domain`` is set, it will override the value of
    :envvar:`COOKIE_DOMAIN`.

    Example:

    .. code-block:: nginx
        :emphasize-lines: 3,13

        location /auth {
            proxy_pass http://nginx-ldap-auth-service:8888/auth;
            proxy_set_header X-Cookie-Domain ".example.com";

            # other lines omitted for brevity
        }

        location /check-auth {
            proxy_pass http://nginx-ldap-auth-service:8888/check;

            # other lines omitted for brevity

            proxy_set_header X-Cookie-Domain ".example.com";
        }

X-Auth-Realm

    The title for the login form.  This goes in the ``location`` block for the
    ``/auth`` location. Defaults to the value of
    :py:attr:`nginx_ldap_auth.settings.Settings.auth_realm` for the
    ``nginx-ldap-auth-service`` instance.  You should either set it here in
    ``nginx.conf`` or with the :envvar:`AUTH_REALM` environment variable, but
    not both.

    Example:

    .. code-block:: nginx
        :emphasize-lines: 3

        location /auth {
            proxy_pass http://nginx-ldap-auth-service:8888/auth;
            proxy_set_header X-Auth-Realm "My Login Form";
        }

.. _nginx-ldap-auth-service-env:

Environment
-----------

You can either export the appropriate variables directly into your shell
environment, or you can use an environment file and specify it with the
``--env-file`` option to ``nginx-ldap-auth start``.

The following environment variables are available to configure
``nginx-ldap-auth-service``:

.. important::

    You must set at least these variables to localize to your organization:

    * :envvar:`LDAP_URI`
    * :envvar:`LDAP_BINDDN`
    * :envvar:`LDAP_PASSWORD`,
    * :envvar:`LDAP_BASEDN`
    * :envvar:`SECRET_KEY`.
    * :envvar:`CSRF_SECRET_KEY`.

    You should also look at these variables to see whether their defaults work
    for you:

    * :envvar:`LDAP_USERNAME_ATTRIBUTE`
    * :envvar:`LDAP_FULL_NAME_ATTRIBUTE`
    * :envvar:`LDAP_GET_USER_FILTER`
    * :envvar:`LDAP_AUTHORIZATION_FILTER`
    * :envvar:`AUTH_REALM`
    * :envvar:`SESSION_MAX_AGE`

Web Server
^^^^^^^^^^

These settings configure the web server that ``nginx-ldap-auth-service`` runs,
``uvicorn``.

.. envvar:: HOSTNAME

    The hostname to listen on. Defaults to ``0.0.0.0``.

.. envvar:: PORT

    The port to listen on. Defaults to ``8888``.

.. envvar:: SSL_KEYFILE

    The path to the SSL key file. Defaults to ``/certs/server.key``.

.. envvar:: SSL_CERTFILE

    The path to the SSL certificate file. Defaults to ``/certs/server.crt``.

.. envvar:: WORKERS

    The number of worker processes to spawn. Defaults to ``1``.

.. envvar:: DEBUG

    Set to ``1`` or ``True`` to enable debug mode. Defaults to ``False``.


Login form and sessions
^^^^^^^^^^^^^^^^^^^^^^^

These settings configure the login form and session handling.

.. envvar:: AUTH_REALM

    The title for the login form. Defaults to ``Restricted``.

.. envvar:: COOKIE_NAME

    The name of the cookie to use for the session. Defaults to ``nginxauth``.

.. envvar:: CSRF_COOKIE_NAME

    The name of the cookie to use for the CSRF cookie. Defaults to whatever you
    set :envvar:`COOKIE_NAME` to with ``_csrf`` appended.

.. envvar:: COOKIE_DOMAIN

    The domain for the cookie to use for the session. Defaults to no domain.

.. envvar:: SESSION_MAX_AGE

    How many seconds a session should last after first login.  Defaults to
    ``0``, no expiry.   If :envvar:`USE_ROLLING_SESSIONS` is ``True``, this
    value is used to reset the session lifetime on every request.

.. envvar:: USE_ROLLING_SESSIONS

    If ``True``, session lifetime will be reset to :envvar:`SESSION_MAX_AGE` on
    every request.  Defaults to ``False``.

.. envvar:: SECRET_KEY

    **Required** The secret key to use for the session.

.. envvar:: CSRF_SECRET_KEY

    **Required** The secret key to use for the CSRF cookie.

.. envvar:: SESSION_BACKEND

    The session backend to use. Defaults to ``memory``.  Valid options are
    ``memory`` and ``redis``.  If you choose ``redis``, you must also set
    :envvar:`REDIS_URL`.

.. envvar:: REDIS_URL

    The DSN to the Redis server.  See :py:attr:`nginx_ldap_auth.settings.Settings.redis_url` for details on the format of the DSN.

    Defaults to ``None``

.. envvar:: REDIS_PREFIX

    The prefix to use for Redis keys. Defaults to ``nginx_ldap_auth``.


LDAP
^^^^

These settings configure the LDAP server to use for authentication.

.. envvar:: LDAP_URI

    **Required**. The URL to the LDAP server. Defaults to ``ldap://localhost``.

.. envvar:: LDAP_BINDDN

    **Required**. The DN to use to bind to the LDAP server for doing our user
    and authorization searches.

.. envvar:: LDAP_PASSWORD

    **Required**. The password to use to with :envvar:`LDAP_BINDDN` to bind to
    the LDAP server for doing our user and authorization searches.

.. envvar:: LDAP_STARTTLS

    Set to ``1`` or ``True`` to enable STARTTLS on our LDAP connections. Defaults to ``False``.

.. envvar:: LDAP_DISABLE_REFERRALS

    Set to ``1`` or ``True`` to disable LDAP referrals. Defaults to ``False``.

.. envvar:: LDAP_BASEDN

    **Required** The base DN to use for our LDAP searches.

.. envvar:: LDAP_USERNAME_ATTRIBUTE

    The LDAP attribute to use for the username. Defaults to ``uid``.

.. envvar:: LDAP_FULL_NAME_ATTRIBUTE

    The LDAP attribute to use for the full name. Defaults to ``cn``.

.. envvar:: LDAP_GET_USER_FILTER

    The LDAP search filter to use when searching for users. Defaults to
    ``{username_attribute}={username}``, where ``{username_attribute}`` is the
    value of :envvar:`LDAP_USERNAME_ATTRIBUTE` and ``{username}`` is the
    username provided by the user.  See :py:attr:`nginx_ldap_auth.settings.Settings.ldap_get_user_filter` for more details.

    The filter will within the base DN given by :envvar:`LDAP_BASEDN` and with
    scope of ``SUBTREE``.

.. envvar:: LDAP_AUTHORIZATION_FILTER

    The LDAP search filter to use when determining if a user is authorized to login.
    for authorizations. Defaults to no filter, meaning all users are authorized if
    they exist in LDAP. See :py:attr:`nginx_ldap_auth.settings.Settings.ldap_authorization_filter` for more details.

    The filter will within the base DN given by :envvar:`LDAP_BASEDN` and with
    scope of ``SUBTREE``.

.. envvar:: LDAP_TIMEOUT

    The maximum number of seconds to wait when acquiring a connection to the LDAP
    server. Defaults to ``15``.

.. envvar:: LDAP_MIN_POOL_SIZE

    The minimum number of connections to keep in the LDAP connection pool. Defaults
    to ``1``.

.. envvar:: LDAP_MAX_POOL_SIZE

    The maximum number of connections to keep in the LDAP connection pool. Defaults
    to ``30``.

.. envvar:: LDAP_POOL_CONNECTION_LIFETIME_SECONDS

    The maximum number of seconds to keep a connection in the LDAP connection pool.
    Defaults to ``20``.
