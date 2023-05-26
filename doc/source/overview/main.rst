********
Overview
********

`nginx-ldap-auth-service` provides a method of authenticating users who request
protected resources from servers proxied by [nginx](https://www.nginx.com/)
against an LDAP or Active Directory server.  It provides a daemon
(`nginx-ldap-auth`) that communicates with an LDAP or Active Directory server
to authenticate users with their username and password, as well as a login form
for actually allowing users to authenticate.

Features
========

User authentication
-------------------

- Login form and page
- Login sessions backed by Redis
- Integration with the [nginx_http_auth_request_module](http://nginx.org/en/docs/http/ngx_http_auth_request_module.html)

Other features
--------------
- Implemented in [FastAPI](https://fastapi.tiangolo.com/) for speed and
  connection management.
