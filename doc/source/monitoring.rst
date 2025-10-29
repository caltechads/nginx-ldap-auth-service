.. _monitoring:

Monitoring nginx_ldap_auth_service
==================================

nginx_ldap_auth_service provides two endpoints for monitoring the status of the
auth service and the LDAP connection.

- ``/status`` - Returns the status of the auth service.
- ``/status/ldap`` - Returns the status of the LDAP connection.

These endpoints are useful for monitoring the health of the auth service and the
LDAP connection.

.. important::

    Note that you have to be able to reach the ``/status`` and ``/status/ldap``
    endpoints on the auth service itself in order to get the status of the auth
    service and the LDAP connection.   This means you need to carefully expose
    these endpoints to your monitoring system without exposing them to the
    public.

/status
-------

The ``/status`` endpoint does not do any checks on any backend services, it only
answers when asked, if it is able.  The purpose of this endpoint is to provide a
simple way to monitor whether the auth service is running and responding to
requests.

The ``/status`` endpoint returns the status of the auth service.  It will return
a JSON object with the following fields:

- ``status`` - The status of the auth service.  This will always be ``ok``.
- ``message`` - this will always be ``Auth service is running``.



If the auth service is running, you'll get a 200 OK response.  If the auth
service is not running, you'll get a timeout error, since the error condition
monitored here is that the auth service is not responding to requests.

/status/ldap
------------

The ``/status/ldap`` endpoint does a simple connect to the LDAP server to see if
the LDAP connection is successful.  Use this endpoint to monitor the health of
the LDAP connection.

.. important::

    If ``/status`` is not responding, this endpoint won't respond either, since
    that means the auth service is not running or is not responding to requests.

The ``/status/ldap`` endpoint returns the status of the LDAP connection.  It
will return a JSON object with the following fields:

- ``status`` - The status of the LDAP connection.  This will be ``ok`` if the LDAP connection is successful, otherwise it will be ``error``.
- ``message`` - The message of the status.  This will be the error message if the LDAP connection is not successful.

If the LDAP connection is successful, you'll get a 200 OK response.  If the LDAP
connection is not successful, you'll get a 500 Internal Server Error response.
