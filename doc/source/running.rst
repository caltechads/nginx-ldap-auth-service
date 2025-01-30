Running nginx_ldap_auth_service
===============================

.. highlight:: bash

You can run ``nginx_ldap_auth_service`` as daemon running alongside your nginx
process on your web server, or as a Docker sidecar container.

.. _nginx_ldap_auth-cmd:

nginx-ldap-auth command line
----------------------------

After installing ``nginx_ldap_auth_service`` you will have access to the command
line script ``nginx-ldap-auth``.

Basic usage::

    $ nginx-ldap-auth start [OPTIONS]


Positional and keyword arguments can also be passed, but it is recommended to
load configuration from environment variables or with the ``--env-file`` option
rather than the command line.

Arguments
^^^^^^^^^

* ``-env-file FILE`` - Specify an environment file to use to configure
  ``nginx-ldap-auth-service``. This is the recommended way to configure
  ``nginx-ldap-auth-service``.  Note that you can't configure any of
  the below options with an environment file; those environment variables
  if used must be set in the shell environment.

* ``-h BIND, --host=BIND`` - Specify an IP address to which to bind.  Defaults
  to the value of the ``HOST`` environment variable or ``0.0.0.0``
* ``-p PORT, --port=PORT`` - Specify an port to which to bind.  Defaults
  to the value of the ``PORT`` environment variable or ``8888``
* ``-w WORKERS, --workers=WORKERS`` - Number of worker processes. Defaults to
  the value of the ``WORKERS`` environment variable, or ``1`` if neither is set.
* ``--keyfile=KEYFILE`` - Specify a keyfile to use for SSL.  Defaults to the
  value of the ``SSL_KEYFILE`` environment variable, or ``/certs/server.key``.
  ``/certs/server.key``.
* ``--certfile=CERTFILE`` - Specify a certfile to use for SSL.  Defaults to
  the value of the ``SSL_CERTFILE`` environment variable, or ``/certs/server.crt``.

Deployments
-----------

Docker sidecar container
^^^^^^^^^^^^^^^^^^^^^^^^

The preferred way to run ``nginx_ldap_auth_service`` is as a Docker sidecar
container.  This allows you to run ``nginx_ldap_auth_service`` alongside your
nginx container, and have nginx talk to it when it needs to perform authentication
or authorization.

Here is an example ``docker-compose.yml`` file that runs ``nginx`` and
``nginx_ldap_auth_service``:

.. code-block:: yaml

    services:
      nginx:
        image: nginx:latest
        container_name: nginx
        ports:
          - "8443:443"
        volumes:
          - ./etc/nginx/nginx.conf:/etc/nginx/nginx.conf
          - ./etc/nginx/certs:/certs
        depends_on:
          - nginx_ldap_auth_service
        links:
          - nginx_ldap_auth_service

      nginx_ldap_auth_service:
        image: caltechads/nginx-ldap-auth-service:latest
        hostname: auth-service
        container_name: nginx-ldap-auth-service
        ports:
          - "8888:8888"
        environment:
          - LDAP_URI=ldap://ldap.example.com
          - LDAP_BASEDN=dc=example,dc=com
          - LDAP_BINDDN=cn=readonly,dc=example,dc=com
          - LDAP_PASSWORD=readonly
          ...


Kubernetes/AWS Elastic Container Service deployment details are left as an exercise
for the reader.

As a daemon
^^^^^^^^^^^

``nginx-ldap-auth-service`` runs only in the foreground and it writes its logs
to stdout, so if you want to run it as a daemon you will need to use a process
manager like ``supervisord`` or ``systemd`` that can put it in the background and
capture its output.

Here is an example of running it with ``supervisord``.  First make the log folder:

.. code-block:: shell

  $ mkdir -p /var/log/nginx-ldap-auth-service
  $ chown $supervisor_user /var/log/nginx-ldap-auth-service

Then configure ``supervisord`` to run ``nginx-ldap-auth-service`` as a daemon.
Below we've configured it to read its configuration from an environment file.
See :ref:`nginx_ldap_auth-cmd` and :ref:`nginx-ldap-auth-service-env`) for
details about the environment variables that can be set in the environment file.

.. code-block::

    [program:nginx-ldap-auth-service]
    command=/path/to/nginx-ldap-auth --env-file /path/to/env-file
    directory=/tmp
    childlogdir=/var/log/nginx-ldap-auth-service
    stdout_logfile=/var/log/nginx-ldap-auth-service/stdout.log
    stdout_logfile_maxbytes=1MB
    redirect_stderr=true
    user=nobody
    autostart=true
    autorestart=true
    redirect_stderr=true

