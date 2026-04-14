=======================
nginx-ldap-auth-service
=======================

.. toctree::
   :hidden:
   :caption: Overview

   changelog
   installation
   running
   configuration
   nginx
   monitoring
   contributing

.. toctree::
   :caption: Developer Interface
   :hidden:

   api/views.rst
   api/models.rst
   api/ldap.rst
   api/middleware.rst
   api/settings.rst


``nginx-ldap-auth-service`` provides a daemon (``nginx-ldap-auth``) that
communicates with an LDAP or Active Directory server to authenticate users with
their username and password, as well as a login form for actually allowing users
to authenticate.  You can use this in combination with the nginx module
`ngx_http_auth_request_module <http://nginx.org/en/docs/http/ngx_http_auth_request_module.html>`_
to provide authentication for your nginx server.

Features
========

User authentication
-------------------

- Built for use with the
  `ngx_http_auth_request_module <http://nginx.org/en/docs/http/ngx_http_auth_request_module.html>`_
- Provides its own login form and authentication backend
- Users login once via the login form, creating a login session that will be
  used for all subsequent requests to determine that the user is logged in.
- Session data can be either in memory or Redis for high availability and session
  persistence though server restarts.
- The same ``nginx_ldap_auth_service`` server can be used by multiple nginx
  servers.  This allows you to use a single login form for multiple sites
  (single signon like), or you can configure each nginx server to use different
  session cookies so that login sessions are not shared between sites.
- Optional Duo MFA workflow after LDAP authentication.  See :ref:`duo_mfa` for more information.

User authorization
------------------

- Users can be authorized to access resources based on an LDAP search filter
  you supply.
- Supports Kerberos/SPNEGO authentication for Single Sign-On (SSO) environments.
  NGINX handles Kerberos authentication while this service performs LDAP group
  authorization. See :ref:`kerberos_spnego` for configuration details.

Other features
--------------
- Implemented in `FastAPI <https://fastapi.tiangolo.com/>`_ for speed and
  connection management.
- Available a Docker image that can be used as a sidecar container with nginx.