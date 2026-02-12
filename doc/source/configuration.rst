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

.. note::

    Active Directory works somewhat differently than other LDAP servers.

    See the "Active Directory" section in :ref:`nginx-ldap-auth-service-env`
    for more information.

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


Mandatory Headers
-----------------

The following headers are mandatory and must be set in the ``/auth`` location:

- ``X-Proto-Scheme``
- ``X-Host``
- ``Cookie``

In the ``/check-auth`` location, you must set the ``X-Cookie-Name`` header.
See :ref:`nginx_header_config` for more details on how to set these headers.

Cookie

    The Cookies from the user's browser.  This is a mandatory header that is
    used to pass the session cookie and CSRF cookie to the auth service.  It
    should be set like so in the ``/auth`` and ``/check-auth`` locations:

    .. code-block:: nginx
        :emphasize-lines: 3

        location /auth {
            proxy_pass http://nginx-ldap-auth-service:8888/auth;
            proxy_set_header Cookie $http_cookie;
        }

X-Proto-Scheme

    The protocol scheme to use for the auth service.  This is a mandatory header
    that is used to build the redirect_uri for Duo MFA, and to validate the URL
    requested by the user before auth.  It should be set like so in the ``/auth``
    location:

    .. code-block:: nginx
        :emphasize-lines: 3

        location /auth {
            proxy_pass http://nginx-ldap-auth-service:8888/auth;
            proxy_set_header X-Proto-Scheme $scheme;
        }

X-Host

    The real hostname of the site that is requesting authentication.  This is a
    **mandatory** header that is used to validate the URL requested by the user
    before auth.  It should be set like so in the ``/auth`` location:

    We're using ``X-Host`` instead of ``Host`` because the ``Host`` header is
    ALWAYS set.  If you don't pass in the real hostname of the site, then Host
    will be set to the hostname from the ``proxy_pass`` line.

    .. code-block:: nginx
        :emphasize-lines: 3

        location /auth {
            proxy_pass http://nginx-ldap-auth-service:8888/auth;
            proxy_set_header X-Host $host;
        }

    .. note::
        You may need to set this to a specific hostname if you are using a proxy or load balancer.

        Example:

        .. code-block:: nginx
            :emphasize-lines: 3

            location /auth {
                proxy_pass http://nginx-ldap-auth-service:8888/auth;
                proxy_set_header X-Host "www.example.com";
            }

Optional Headers
----------------

The following headers are optional and can be set in the ``/auth`` and ``/check-auth`` locations:

- ``X-Cookie-Name``
- ``X-Cookie-Domain``
- ``X-Auth-Realm``
- ``X-Authenticated-User``
- ``X-Authorization-Filter``

Or they can be set in the environment variables if you have a single backend.

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

X-Authenticated-User

    The username of the authenticated user from ``nginx-ldap-auth-service``.
    This goes in the ``location`` block for your app's location.  This is used
    to pass the authenticated username back to your application so that it can
    be used for provisioning users or other purposes.  This is not required.  be
    used for authorization checks.

    Example:

    .. code-block:: nginx
        :emphasize-lines: 3,4

        location / {
            auth_request /check-auth;
            auth_request_set $auth_user $upstream_http_x_authenticated_user;
            proxy_set_header X-Authenticated-User $auth_user;
        }

X-Authorization-Filter

    An optional header to specify the LDAP authorization filter to use for the request.
    The ``proxy_set_header X-Authorization-Filter`` line goes in the ``location`` block
    for the ``/auth`` and ``/check-auth`` locations.

    If ``X-Authorization-Filter`` is set, then it will override
    :py:attr:`nginx_ldap_auth.settings.Settings.ldap_authorization_filter` for the
    ``nginx-ldap-auth-service`` instance.

    .. important::
        Since this is a per-user authorization filter, the filter must use the
        ``{username}`` placeholder, and must be a valid LDAP search filter.

    This header can be used if multiple services with different LDAP filter requirements
    use the same ``nginx-ldap-auth-service`` instance (e.g different AD groups).

    .. warning::

        This header is only respected when
        :envvar:`ALLOW_AUTHORIZATION_FILTER_HEADER` is ``True`` (the default).

        **Security Risk**: If this setting is enabled and your NGINX configuration
        does not explicitly set or clear the ``X-Authorization-Filter`` header,
        malicious clients could send a permissive filter (e.g., ``(objectClass=*)``)
        to bypass group-based authorization restrictions.

        For secure deployments, either:

        * Set :envvar:`ALLOW_AUTHORIZATION_FILTER_HEADER` to ``False`` and use only
          the :envvar:`LDAP_AUTHORIZATION_FILTER` environment variable, or
        * Ensure your NGINX configuration explicitly sets or clears this header
          using ``proxy_set_header`` before forwarding requests.  Like so:

          .. code-block:: nginx
            :emphasize-lines: 3

            location /auth {
              proxy_pass http://nginx-ldap-auth-service:8888/auth;
              proxy_set_header X-Authorization-Filter "";
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
    * :envvar:`COOKIE_NAME`
    * :envvar:`COOKIE_DOMAIN`
    * :envvar:`CSRF_COOKIE_NAME`
    * :envvar:`SESSION_MAX_AGE`
    * :envvar:`USE_ROLLING_SESSIONS`
    * :envvar:`SESSION_BACKEND`
    * :envvar:`REDIS_URL`
    * :envvar:`REDIS_PREFIX`
    * :envvar:`DUO_ENABLED`
    * :envvar:`DUO_HOST`
    * :envvar:`DUO_IKEY`
    * :envvar:`DUO_SKEY`

LDAP (389, openldap, etc.)

    If you're using an LDAP server that's not Active Directory, and you're using
    posixAccount objects, the :envvar:`LDAP_USERNAME_ATTRIBUTE`  and
    :envvar:`LDAP_FULL_NAME_ATTRIBUTE` defaults will probably just work for you.
    You will still need to set/look at the other LDAP settings.

Active Directory

    If you use Active Directory as your LDAP server, you should set the
    :envvar:`LDAP_USERNAME_ATTRIBUTE` to ``sAMAccountName`` and the
    :envvar:`LDAP_FULL_NAME_ATTRIBUTE` to ``cn``.   You will probably
    also need to set :envvar:`LDAP_USER_BASEDN` to the base DN of your users
    which is probably not the same as your :envvar:`LDAP_BASEDN`.  Auth for
    normal users in AD is sometimes done with the ``userPrincipalName`` attribute
    which is the user's email address, thus you would set :envvar:`LDAP_USER_BASEDN`
    to ``@{__YOUR_EMAIL_DOMAIN__}``, (e.g. ``@example.com``) and the bare username
    will be prepended to that to form the bind DN for the user.

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

.. envvar:: INSECURE

    Set to ``True`` to run our auth service web server over HTTP instead of HTTPS. Defaults to ``False``.


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

    The DSN to the Redis server.  See
    :py:attr:`nginx_ldap_auth.settings.Settings.redis_url` for details on the
    format of the DSN.

    Defaults to ``None``

.. envvar:: REDIS_PREFIX

    The prefix to use for Redis keys. Defaults to ``nginx_ldap_auth``.

.. _duo_mfa:

Duo MFA
^^^^^^^

These settings configure the Duo MFA workflow.

.. envvar:: DUO_ENABLED

    Set to ``True`` to enable Duo MFA. Defaults to ``False``.

.. envvar:: DUO_HOST

    **Required if DUO_ENABLED is True**. The Duo API hostname.

.. envvar:: DUO_IKEY

    **Required if DUO_ENABLED is True**. The Duo integration key.

.. envvar:: DUO_SKEY

    **Required if DUO_ENABLED is True**. The Duo secret key.


.. important::

    When enabling Duo MFA, see :ref:`nginx_header_config` for how to set the
    required ``X-Proto-Scheme`` and ``Host`` headers in the ``nginx``
    configuration file so that the Duo MFA workflow can build the Duo callback
    URL correctly.


LDAP
^^^^

These settings configure the LDAP server to use for authentication.

.. envvar:: LDAP_URI

    **Required**. The URL to the LDAP server. Defaults to ``ldap://localhost``.

.. envvar:: LDAP_BINDDN

    **Required**. The DN of a privileged user in your LDAP/AD server that can be
    used to to bind to the LDAP server for doing our user and authorization searches.

.. envvar:: LDAP_PASSWORD

    **Required**. The password to use to with :envvar:`LDAP_BINDDN` to bind to
    the LDAP server for doing our user and authorization searches.

.. envvar:: LDAP_STARTTLS

    Set to ``0`` or ``False`` to disable STARTTLS on our LDAP connections. Defaults to ``True``.

.. envvar:: LDAP_DISABLE_REFERRALS

    Set to ``1`` or ``True`` to disable LDAP referrals. Defaults to ``False``.

.. envvar:: LDAP_BASEDN

    **Required** The base DN to use for our LDAP searches that find users, and to
    construct the DN for the user to bind with, unless ``LDAP_USER_BASEDN`` is also
    set (see below).  For authentication, the user's DN will be constructed as
    ``{LDAP_USERNAME_ATTRIBUTE}={username},{LDAP_BASEDN}``.

.. envvar:: LDAP_USER_BASEDN

    The base DN to append to the user's username when binding.  This is only
    important for Active Directory, where we may need to use the value of
    ``userPrincipalName`` (typically the user's email address) as the username
    intead of the usual LDAP style dn which would be constructed as
    ``sAMAccountName=user,{LDAP_BASEDN}``.  Include the ``@`` at the beginning
    of the value.  The resulting bind DN will be ``{username}{LDAP_USER_BASEDN}``.

    Defaults to ``None``.

    Example:

    .. code-block:: bash

        export LDAP_USER_BASEDN="@example.com"

    This will cause the bind DN to be ``user@example.com``

    This envvar is normally unset, and if so, the bind DN will be constructed
    as ``{LDAP_USERNAME_ATTRIBUTE}={username},{LDAP_BASEDN}``.

.. envvar:: LDAP_USERNAME_ATTRIBUTE

    The LDAP attribute to use for the username. Defaults to ``uid``.

.. envvar:: LDAP_FULL_NAME_ATTRIBUTE

    The LDAP attribute to use for the full name. Defaults to ``cn``.

.. envvar:: LDAP_GET_USER_FILTER

    The LDAP search filter to use when searching for users. Defaults to
    ``{username_attribute}={username}``, where ``{username_attribute}`` is the
    value of :envvar:`LDAP_USERNAME_ATTRIBUTE` and ``{username}`` is the
    username provided by the user.  See
    :py:attr:`nginx_ldap_auth.settings.Settings.ldap_get_user_filter` for more
    details.

    The filter will within the base DN given by :envvar:`LDAP_BASEDN` and with
    scope of ``SUBTREE``.

.. envvar:: LDAP_AUTHORIZATION_FILTER

    The LDAP search filter to use when determining if a user is authorized to login.
    for authorizations. Defaults to no filter, meaning all users are authorized if
    they exist in LDAP. See :py:attr:`nginx_ldap_auth.settings.Settings.ldap_authorization_filter` for more details.

    The filter will within the base DN given by :envvar:`LDAP_BASEDN` and with
    scope of ``SUBTREE``.

.. envvar:: ALLOW_AUTHORIZATION_FILTER_HEADER

    Whether to allow the ``X-Authorization-Filter`` HTTP header to override
    :envvar:`LDAP_AUTHORIZATION_FILTER`. Defaults to ``True`` for backwards
    compatibility.

    .. warning::

        Setting this to ``True`` without properly configuring NGINX to control
        the ``X-Authorization-Filter`` header is a **security risk**. Malicious
        clients could send a permissive filter (e.g., ``(objectClass=*)``) to
        bypass group-based authorization restrictions.

        For secure deployments, set this to ``False`` and use only the
        :envvar:`LDAP_AUTHORIZATION_FILTER` environment variable, or ensure your
        NGINX configuration explicitly sets or clears the header using
        ``proxy_set_header`` before forwarding requests.

    .. note::

        The default is ``True`` for backwards compatibility. Future versions
        may change the default to ``False`` for improved security.

    See :py:attr:`nginx_ldap_auth.settings.Settings.allow_authorization_filter_header`
    for more details.

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
