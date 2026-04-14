.. _nginx:

Configuring nginx
=================

This page describes how to configure nginx to use ``nginx-ldap-auth-service`` to
protect your site using LDAP.

There are two authentication modes supported:

1. **Form-based authentication** (default) - Users are presented with a login form
   and authenticate with username/password against LDAP.
2. **Kerberos/SPNEGO authentication** - NGINX handles Kerberos authentication and
   passes the authenticated username to the service for LDAP group authorization.
   See :ref:`kerberos_spnego` for details.

ngx_http_auth_request_module
----------------------------

``nginx-ldap-auth-service`` requires your ``nginx`` to have the
``ngx_http_auth_request_module`` to do its work. To see if your version of nginx
has that installed, do ``nginx -V`` and look for ``--with-http_auth_request_module``:

.. code-block:: bash

    $ nginx -V
    nginx version: nginx/1.23.4
    built by gcc 10.2.1 20210110 (Debian 10.2.1-6)
    built with OpenSSL 1.1.1n  15 Mar 2022
    TLS SNI support enabled
    configure arguments: --prefix=/etc/nginx --sbin-path=/usr/sbin/nginx --modules-path=/usr/lib/nginx/modules --conf-path=/etc/nginx/nginx.conf --error-log-path=/var/log/nginx/error.log --http-log-path=/var/log/nginx/access.log --pid-path=/var/run/nginx.pid --lock-path=/var/run/nginx.lock --http-client-body-temp-path=/var/cache/nginx/client_temp --http-proxy-temp-path=/var/cache/nginx/proxy_temp --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp --http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp --http-scgi-temp-path=/var/cache/nginx/scgi_temp --user=nginx --group=nginx --with-compat --with-file-aio --with-threads --with-http_addition_module --with-http_auth_request_module --with-http_dav_module --with-http_flv_module --with-http_gunzip_module --with-http_gzip_static_module --with-http_mp4_module --with-http_random_index_module --with-http_realip_module --with-http_secure_link_module --with-http_slice_module --with-http_ssl_module --with-http_stub_status_module --with-http_sub_module --with-http_v2_module --with-mail --with-mail_ssl_module --with-stream --with-stream_realip_module --with-stream_ssl_module --with-stream_ssl_preread_module --with-cc-opt='-g -O2 -ffile-prefix-map=/data/builder/debuild/nginx-1.23.4/debian/debuild-base/nginx-1.23.4=. -fstack-protector-strong -Wformat -Werror=format-security -Wp,-D_FORTIFY_SOURCE=2 -fPIC' --with-ld-opt='-Wl,-z,relro -Wl,-z,now -Wl,--as-needed -pie'

nginx.conf
----------

There four bits to this configuration:

#. Configuring your site's ``location`` block to use ``auth_request`` and
   to redirect any unauthenticated requests to the ``nginx-ldap-auth-service``
   login page.
#. Configuring a ``location`` for ``nginx-ldap-auth-service`` to use to
   authenticate and logout users.
#. Configuring the ``location`` that ``auth_request`` will use to
   see if a user is authenticated.
#. (optional) Configuring a cache for the ``auth_request`` location so that we don't
   have to hit the auth service on every request.

Below is a minimal example configuration for a site that uses LDAP to
authenticate users that want to access the site whose root page is ``/``.
You need everything there in order to make it work.

Things to note:

- We serve all the login related views in an ``server`` block that is HTTPS only.
  This is because we don't want to send the user's password over the wire in
  plain text.
- In the ``proxy_pass`` lines below, we're naming the server that hosts the auth
  service ``nginx_ldap_auth_service`` on port 8888.  Change this to whatever
  hostname and port the service answers on in your architecture.
- The login and logout related views are served by ``nginx-ldap-auth-service``
  and always use the paths ``/auth/login`` and ``/auth/logout``, and those paths
  are hard-coded into the login form; you can't change them.   The ``/auth``
  location handles the proxying of those paths to ``nginx-ldap-auth-service``.
- If you set the :envvar:`COOKIE_NAME` environment variable in the
  ``nginx_ldap_auth_service`` service, you need to change the ``proxy_set_header
  Cookie nginxauth`` line in the ``/auth`` location to match that value,
  changing ``nginxauth`` to whatever you set it to in all places in that line.
  You will also need to do the same things to the ``proxy_set_header Cookie``
  and ``proxy_cache_key`` lines in the ``/check-auth`` location.  Finally, you
  will have to change the ``proxy_set_header Cookie nginxauth_conf`` line
  in the ``/auth`` location to match the value of :envvar:`COOKIE_NAME` with
  ``_csrf`` appended, again in all places in that line.
- If you set the :envvar:`CSRF_COOKIE_NAME`, you will have to change the
  ``proxy_set_header Cookie nginxauth_conf`` line in the ``/auth`` location to
  match that value with in all places in that line.
- See :ref:`nginx_header_config` for information on how to configure
  ``nginx-ldap-auth-service`` behavior using custom headers. **Some headers are mandatory for 2.5.0 and later.**

.. code-block:: nginx
    :emphasize-lines: 12,24,28,29,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71

    user nginx;
    worker_processes auto;

    error_log  /dev/stderr info;
    pid /tmp/nginx.pid;

    events {
      worker_connections 1024;
    }

    http {
      proxy_cache_path /tmp/nginx-cache keys_zone=auth_cache:10m;
      include /etc/nginx/mime.types;
      default_type application/octet-stream;

      server {
        listen 443 ssl;
        http2 on;

        ssl_certificate /certs/localhost.crt;
        ssl_certificate_key /certs/localhost.key;

        location / {
            auth_request /check-auth;
            root   /usr/share/nginx/html;
            index  index.html index.htm;

            # If the auth service returns a 401, redirect to the login page.
            error_page 401 =200 /auth/login?service=$request_uri;
        }

        location /auth {
            proxy_pass https://nginx_ldap_auth_service:8888/auth;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            # We need to pass in the the cookies so we can acess both the CSRF and
            # session cookies in the login workflow.
            proxy_set_header Cookie $http_cookie;
            # We need these headers to build the redirect_uri for Duo MFA,
            # and to validate the URL requested by the user before auth.
            proxy_set_header X-Proto-Scheme $scheme;
            proxy_set_header X-Host $host;
            # If you are not using X-Authorization-Filter in your configuration, block it
            # so that malicious clients can't use it to bypass our settings
            # proxy_set_header X-Authorization-Filter "";
        }

        location /check-auth {
            internal;
            proxy_pass https://nginx_ldap_auth_service:8888/check;

            # Ensure that we don't pass the user's headers or request body to
            # the auth service.
            proxy_pass_request_headers off;
            proxy_pass_request_body off;
            proxy_set_header Content-Length "";

            # We use the same auth service for managing the login and logout and
            # checking auth.  The SessionMiddleware, which is used for all requests,
            # will always be trying to set cookies even on our /check path.  Thus we
            # need to ignore the Set-Cookie header so that nginx will cache the
            # response.  Otherwise, it will think this is a dynamic page that
            # shouldn't be cached.
            proxy_ignore_headers "Set-Cookie";
            proxy_hide_header "Set-Cookie";

            # Cache our auth responses for 10 minutes so that we're not
            # hitting the auth service on every request.
            proxy_cache auth_cache;
            proxy_cache_valid 200 10m;

            proxy_set_header Cookie nginxauth=$cookie_nginxauth;
            proxy_cache_key "$http_authorization$cookie_nginxauth";
        }
      }
    }


.. _kerberos_spnego:

Kerberos/SPNEGO Authentication
------------------------------

If your environment uses Kerberos authentication (common in enterprise environments
with Active Directory), you can configure NGINX to handle SPNEGO authentication
while using ``nginx-ldap-auth-service`` for LDAP group-based authorization.

This approach provides:

- **Single Sign-On (SSO)**: Users authenticate automatically via their Kerberos tickets
- **Stateless authorization**: No session cookies required for the authorization check
- **Group-based access control**: Authorize users based on LDAP group membership
- **High performance**: Authorization results are cached to reduce LDAP load

Prerequisites
~~~~~~~~~~~~~

1. NGINX compiled with the ``ngx_http_auth_spnego_module`` or similar Kerberos module
2. A valid Kerberos keytab file for your web service
3. Users with valid Kerberos tickets (e.g., domain-joined workstations)

How it works
~~~~~~~~~~~~

1. User requests a protected resource
2. NGINX negotiates Kerberos authentication via SPNEGO
3. On successful authentication, NGINX sets ``$remote_user`` to the authenticated principal
4. NGINX calls ``/check-header`` on ``nginx-ldap-auth-service``, passing the username
5. The service checks LDAP group membership and returns 200 (authorized) or 403 (forbidden)
6. NGINX grants or denies access based on the response

NGINX Configuration
~~~~~~~~~~~~~~~~~~~

Below is a complete example configuration for Kerberos/SPNEGO authentication with
LDAP group authorization.

.. important::

    **Security**: The ``X-Ldap-User`` header must be set by NGINX, not passed through
    from the client. The configuration below uses ``proxy_pass_request_headers off``
    to prevent header spoofing.

.. code-block:: nginx

    user nginx;
    worker_processes auto;

    error_log  /dev/stderr info;
    pid /tmp/nginx.pid;

    events {
      worker_connections 1024;
    }

    http {
      include /etc/nginx/mime.types;
      default_type application/octet-stream;

      server {
        listen 443 ssl;
        http2 on;

        ssl_certificate /certs/localhost.crt;
        ssl_certificate_key /certs/localhost.key;

        # Kerberos authentication settings
        auth_gss on;
        auth_gss_keytab /etc/krb5.keytab;
        auth_gss_realm EXAMPLE.COM;
        auth_gss_service_name HTTP;

        location / {
            # Require Kerberos authentication
            auth_gss on;

            # Use auth_request to check LDAP group membership
            auth_request /check-header-auth;

            # Pass the authenticated user to the backend application
            auth_request_set $auth_user $upstream_http_x_auth_user;
            proxy_set_header X-Authenticated-User $auth_user;

            root /usr/share/nginx/html;
            index index.html index.htm;

            # Return 403 if authorization fails (user not in required group)
            error_page 403 = @forbidden;
        }

        location @forbidden {
            return 403 "Access denied: You are not authorized to access this resource.";
        }

        location /check-header-auth {
            internal;
            proxy_pass https://nginx_ldap_auth_service:8888/check-header;

            # IMPORTANT: Do not pass client headers to prevent spoofing
            proxy_pass_request_headers off;
            proxy_pass_request_body off;
            proxy_set_header Content-Length "";

            # Pass the Kerberos-authenticated username
            # $remote_user is set by auth_gss after successful authentication
            proxy_set_header X-Ldap-User $remote_user;

            # Optional: Specify LDAP authorization filter
            # Users must be members of the "web-users" group
            proxy_set_header X-Authorization-Filter "(&(sAMAccountName={username})(memberOf=cn=web-users,ou=Groups,dc=example,dc=com))";

            # Prevent caching in NGINX (the service has its own cache)
            proxy_no_cache 1;
            proxy_cache_bypass 1;
        }
      }
    }

Configuration Notes
~~~~~~~~~~~~~~~~~~~

X-Ldap-User Header

    The header containing the authenticated username. By default, this is
    ``X-Ldap-User``, but you can change it with the :envvar:`LDAP_TRUSTED_USER_HEADER`
    environment variable.

    .. code-block:: nginx

        # Extract just the username from user@REALM format
        map $remote_user $kerberos_user {
            ~^(?<user>[^@]+)@  $user;
            default            $remote_user;
        }

        location /check-header-auth {
            # ...
            proxy_set_header X-Ldap-User $kerberos_user;
        }

X-Authorization-Filter Header

    The LDAP filter used to determine authorization. If not specified, the service
    uses the :envvar:`LDAP_AUTHORIZATION_FILTER` environment variable.

    .. code-block:: nginx

        # Different filters for different locations
        location /admin {
            auth_request /check-header-auth-admin;
            # ...
        }

        location /check-header-auth-admin {
            internal;
            proxy_pass https://nginx_ldap_auth_service:8888/check-header;
            proxy_set_header X-Ldap-User $remote_user;
            proxy_set_header X-Authorization-Filter "(&(sAMAccountName={username})(memberOf=cn=admins,ou=Groups,dc=example,dc=com))";
            # ...
        }

Response Codes

    The ``/check-header`` endpoint returns:

    - **200 OK**: User is authorized (also sets ``X-Auth-User`` response header)
    - **401 Unauthorized**: Missing username header (Kerberos auth failed upstream)
    - **403 Forbidden**: User exists but is not in the required LDAP group
    - **500 Internal Server Error**: LDAP connection error

Caching Behavior

    The service includes a built-in authorization cache (default TTL: 5 minutes)
    to reduce LDAP load. You can configure this with:

    - :envvar:`HEADER_AUTH_CACHE_TTL`: Cache duration in seconds (0 to disable)

    The cache is keyed by username + authorization filter hash, so different
    filters result in separate cache entries.
