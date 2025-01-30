.. _runbook__contributing:

Contributing
============

Instructions for contributors
-----------------------------

In order to make a clone of the Github repo:

.. code-block:: shell

    $ git clone https://github.com/caltechads/nginx-ldap-auth-service.git


Workflow is pretty straightforward:

#. Make sure you are reading the latest version of this document.
#. Setup your machine with the required development environment
#. Checkout a new branch, named for yourself and a summary of what you're trying to accomplish.
#. Make a change
#. Make sure all tests passed
#. Update the documentation and ensure that it looks correct.
#. Commit changes to your branch
#. Merge your changes into master and push.


Preconditions for working on nginx-ldap-auth-service
----------------------------------------------------

You'll need some version of Python 3.11 installed, and ``uv`` and ``pip``.

.. code-block:: shell

   $ cd nginx-ldap-auth-service
   $ pip install uv
   $ uv venv
   $ source .venv/bin/activate
   $ uv sync --extra=docs

After that please install libraries into your ``uv`` tool folder that are
required for development:

.. code-block:: shell

   $ uv tool install ruff
   $ uv tool install twine
   $ uv tool install bumpversion

Precondiions for running the docker-compose stack in development
----------------------------------------------------------------

Since ``nginx-ldap-auth-service`` authenticates against an LDAP or Active
Directory service, you will need to provide one.  The LDAP/AD server you use
needs these features:

* It must support ``STARTTLS``
* It must support ``LDAPv3``
* It must support ``SIMPLE`` bind
* It must have an account that with sufficient privileges to bind to the LDAP/AD
  server with a password and search for users.

Prepare the docker environment
------------------------------

Now copy in the Docker environment file to the appropriate place on your dev box:

.. code-block:: shell

    $ cp etc/environment.txt .env

Edit ``.env`` replace these with settings appropriate for your LDAP/AD server:

- ``__LDAP_URI__``
- ``__LDAP_BINDDN__``
- ``__LDAP_BASEDN__``
- ``__LDAP_PASSWORD__``

Build the Docker image
----------------------

.. code-block:: shell

    $ make build

Run the stack
-------------

.. code-block:: shell

    $ make dev

This will bring up the full dev stack:

- ``nginx``
- ``nginx-ldap-auth-service``

If you want to bring up a redis instance for session storage, you can do that by
uncommenting the ``redis`` service in ``docker-compose.yml`` and adding these
two settings to the ``environment`` section of the ``nginx_ldap_auth_service``
service::

    - SESSION_BACKEND=redis
    - REDIS_URL=redis://redis:6379/0

Use your dev environment
------------------------

You should how be able to browse to https://localhost/ and be redirected to
the login page.

