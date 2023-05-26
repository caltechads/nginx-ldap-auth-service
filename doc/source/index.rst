=======================
nginx-ldap-auth-service
=======================

.. toctree::
   :caption: Overview
   :hidden:

   overview/main

.. toctree::
   :caption: Runbook
   :hidden:

   runbook/main

.. toctree::
   :caption: Developer Interface
   :hidden:

   api/views.rst
   api/models.rst
   api/session.rst
   api/settings.rst


`nginx-ldap-auth-service` provides a method of authenticating users who request
protected resources from servers proxied by [nginx](https://www.nginx.com/)
against an LDAP or Active Directory server.  It provides a daemon
(`nginx-ldap-auth`) that communicates with an LDAP or Active Directory server
to authenticate users with their username and password, as well as a login form
for actually allowing users to authenticate.

The `nginx-ldap-auth` server utilizes the `ngx_http_auth_request_module` to do
its work.