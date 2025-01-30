Installation
============

.. highlight:: bash

:Requirements: **Python 3.x >= 3.11**

To install the latest released version::

  $ pip install nginx-ldap-auth-service

From Source
-----------

You can install ``nginx-ldap-auth-service`` from source just as you would
install any other Python package::

    $ pip install git+https://github.com/caltechads/nginx-ldap-auth-service.git

This will allow you to keep up to date with development on GitHub::

    $ pip install -U git+https://github.com/caltechads/nginx-ldap-auth-service.git

From Docker Hub
---------------

You can also run ``nginx-ldap-auth-service`` from Docker Hub::

    $ docker pull caltechads/nginx-ldap-auth-service:latest
    $ docker run \
        -d \
        -p 8888:8888 \
        -e LDAP_URI=ldap://ldap.example.com \
        -e LDAP_BASEDN=dc=example,dc=com \
        -e LDAP_BINDDN=cn=admin,dc=example,dc=com \
        -e LDAP_PASSWORD=secret \
        caltechads/nginx-ldap-auth-service

Or use ``docker-compose``. Create a ``docker-compose.yml`` file with the
following contents::

    services:
      nginx_ldap_auth_service:
        image: caltechads/nginx-ldap-auth-service:latest
        hostname: nginx-ldap-auth-service
        container_name: nginx-ldap-auth-service
        ports:
          - 8888:8888
        environment:
          - LDAP_URI=ldap://ldap.example.com
          - LDAP_BASEDN=dc=example,dc=com \
          - LDAP_BINDDN=cn=admin,dc=example,dc=com
          - LDAP_PASSWORD=secret

Then run::

    $ docker-compose up -d
