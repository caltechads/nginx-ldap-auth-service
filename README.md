# nginx-ldap-auth-service

`nginx-ldap-auth-service` provides a daemon (`nginx-ldap-auth`) that
communicates with an LDAP or Active Directory server to authenticate users with
their username and password, as well as a login form for actually allowing users
to authenticate.  You can use this in combination with the nginx module
[ngx_http_auth_request_module](http://nginx.org/en/docs/http/ngx_http_auth_request_module.html)
to provide authentication for your nginx server.

See the [Documentation](https://nginx-ldap-auth-service.readthedocs.io) for more
information.