CHANGELOG
=========

2.6.2 (2026-02-21)
------------------

Enhancements
^^^^^^^^^^^^

- Added the ``LDAP_VALIDATE_CERT`` setting.  If set to ``False``, the auth service will not validate the LDAP certificate.  Defaults to ``True``.
, ``LDAP_CA_CERT_NAME`` and ``LDAP_CA_CERT_DIR`` settings.  If both are set, the auth service will use the CA certificate to validate the LDAP certificate.  Both setting default to ``None``.
- updated all dependencies to the latest versions, for the Dockerhub image.

Bugfixes
^^^^^^^^

- @semidark changed ``uvicorn`` startup to use the default TLS 1.2 protocol, a SSLv2 is deprecated.  This is a security enhancement.  This will affect you if you have a ``INSECURE`` set to ``False``.

2.6.1 (2026-02-18)
------------------

Enhancements
^^^^^^^^^^^^

- @kblum added the ``INSECURE`` setting.  If set to ``True``, the auth service will run over HTTP instead of HTTPS.  Defaults to ``False``.
- Updated all dependencies to the latest versions, again for the Dockerhub image.

2.6.0 (2026-02-12)
------------------

Enhancements
^^^^^^^^^^^^

- @semidark Added the ``ALLOW_AUTHORIZATION_FILTER_HEADER`` setting.  If set to ``True``, the auth service will obey the ``X-Authorization-Filter`` header.  If set to ``False``, the ``X-Authorization-Filter`` header will be ignored.  Defaults to ``True`` for backwards compatibility.
- Added validation of the ``X-Authorization-Filter`` header and the ``Settings.ldap_authorization_filter`` setting to ensure they are valid LDAP search filters.
- Added validation of the ``Settings.ldap_get_user_filter`` setting to ensure it is a valid LDAP search filter.

2.5.1 (2026-01-27)
------------------

Bugfixes
^^^^^^^^

- Added an internal test to notify the system administrator if the required headers are not set in the nginx configuration file.

.. important::
    Added this check because 2.5.0 and later needs the ``X-Proto-Scheme`` and
    ``Host`` headers set via ``proxy_set_header`` in the ``/auth`` location of
    the nginx configuration file.  See :ref:`nginx_header_config` for more
    information.


2.5.0 (2026-01-27)
------------------

Enhancements
^^^^^^^^^^^^

- Added optional Duo MFA workflow. This can be enabled by setting ``DUO_ENABLED`` to ``True`` and providing the required Duo configuration settings.  Please read the :ref:`duo_mfa` documentation for more information on how to configure Duo MFA and note that the nginx configuration file needs to be updated to pass the required headers to the auth service.
- Updated all dependencies to the latest versions, again for the Dockerhub image.
- Added a full test suite.

Bugfixes
^^^^^^^^

- The required settings in the nginx configuration file have been changed so that we can sanitize the url passed to the auth service to avoid an exploit allowing an attacker to redirect the user to a malicious service.

2.4.2 (2026-01-16)
------------------

Enhancements
^^^^^^^^^^^^

- @kblum fixed some annoyances in the development environment.

2.4.1 (2026-01-13)
------------------

Enhancements
^^^^^^^^^^^^

- @kblum fixed the status endpoints to not serve malformed JSON, and to not expose data about internal systems

2.4.0 (2026-01-12)
------------------

Enhancements
^^^^^^^^^^^^

- @kblum added the ``X-Authorization-Filter`` header to the auth service via PR #17.  This header can be used to specify the LDAP authorization filter to use for the request, on a per backend basis.
- Now using ``python:3.13-alpine3.23`` as the base image for Dockerhub image.
- Updated all dependencies to the latest versions, again for the Dockerhub image.

2.3.0 (2025-10-29)
------------------

- Added a ``/status`` endpoint to the auth service.  This endpoint returns the status of the auth service.
- Added a ``/status/ldap`` endpoint to the auth service.  This endpoint returns the status of the LDAP connection
- Updated all dependencies to the latest versions.

2.2.0 (2025-10-03)
------------------

Enhancements
^^^^^^^^^^^^

- Added the ``INSECURE`` setting.  If set to ``True``, the auth service will run over HTTP instead of HTTPS -- konrad@spatialedge.ai
- Updated all dependencies to the latest versions.

2.1.8 (2025-06-25)
------------------

Documentation
^^^^^^^^^^^^^

- Corrected the default for ``LDAP_STARTTLS`` to be ``True`` instead of ``False``.

2.1.7 (2025-06-23)
------------------

Enhancements
^^^^^^^^^^^^

- Updated all dependencies to the latest versions.

2.1.6 (2025-05-02)
------------------

Enhancements
^^^^^^^^^^^^

- Added the ``X-Authenticated-User`` header to the response.  This is the username of the authenticated user.  This is useful for  for passing the username to the actual service being authenticated.  [Thanks @micchickenburger]
- Updated all dependencies to the latest versions.
- Now using ``python:3.13-alpine3.21`` as the base image for Dockerhub.
- Updated the Dockerfile build strategy to our best practices here at Caltech.

Documentation
^^^^^^^^^^^^^

- Added the ``changelog`` to the documentation

2.1.5 (2025-03-17)
------------------

Enhancements
^^^^^^^^^^^^

- Now using ``python:3.12-alpine3.21`` as the base image for Dockerhub.

Bugfixes
^^^^^^^^

- Don't distribute wheels -- some people were having issues with them


2.1.4 (2025-02-19)
------------------

Enhancements
^^^^^^^^^^^^

- Added the ``LDAP_USER_BASEDN`` setting.  This is the base DN for the user search.  It defaults to ``LDAP_BASEDN`` if not set. [@JustGitting]
- Updated dependencies to the latest versions.

2.1.3 (2025-02-11)
------------------

Bugfixes
^^^^^^^^

- Actually package the templates and static files in the distribution
- Use :py:attr:`nginx_ldap_auth.Settings.ldap_username_attribute`` and :py:attr:`nginx_ldap_auth.Settings.ldap_full_name_attribute`` to load the user object
- More ReadTheDocs config file fixes

2.1.2 (2025-01-30)
------------------

Bugfixes
^^^^^^^^

- Fixed the messed up ``nosemgrep`` comment in the login template.

2.1.1 (2025-01-30)
------------------

Enhancements
^^^^^^^^^^^^

- Now building multi-arch images for Dockerhub (amd64 and arm64)
- Changed the package name to reflect what modern Python packaging tools expect.  The package is now called ``nginx_ldap_auth`` instead of ``nginx-ldap-auth``.

Bugfixes
^^^^^^^^

- Added pyproject.toml to MANIFEST.in so it gets included in the sdist package
- TERRAFORM: hopefully the runner instance creation now properly installs acrunner

2.1.0 (2025-01-30)
------------------

Enhancements
^^^^^^^^^^^^

- Added CSRF protection to the ``nginx-ldap-auth`` login page.
- Now using ``uv`` for managing the virtualenv and doing packaging

Documentation
^^^^^^^^^^^^^

- Updated :doc:`/contributing` for the new ``uv`` workflow
- Various other documentation updates

2.0.5 (2023-07-23)
------------------

Bugfixes
^^^^^^^^

- Docs build again.


2.0.4 (2023-07-14)
------------------

Enhancements
^^^^^^^^^^^^

- Added ``USE_ROLLING_SESSIONS``.  If ``True``, the session lifetime will be reset on every request.  Defaults to ``False``.
- ``REDIS_URL`` is now required if ``SESSION_BACKEND`` is set to ``ldap``.
- ``LDAP_BASEDN`` is now required.
- ``SECRET_KEY`` is now required.

Bugfixes
^^^^^^^^

- On startup, don't log the full LDAP URL.  This is a security issue, as it may contain sensitive information.

Documentation
^^^^^^^^^^^^^

- Documented ``MAX_SESSION_AGE``.
- Noted which settings are required to localize the app to your environment.
- Various other documentation updates.

2.0.3 (2023-07-11)
------------------

Bugfixes
^^^^^^^^

- Actually obey :py:attr:`nginx_ldap_auth.settings.Settings.ldap_authorization_filter` if it is set.
- ``nginx-ldap-auth`` now chooses the correct cert file.
- Fix typo in ``etc/environment.txt``

Documentation
^^^^^^^^^^^^^

- ReadTheDocs config actually works now.
- Documented how to use ``nginx-ldap-auth`` as a dockerhub Docker container.

2.0.2 (2023-07-11)
------------------

Enhancements
^^^^^^^^^^^^

- Added a ReadTheDocs configuration file

Bugfixes
^^^^^^^^

- Removed ``gunicorn`` from the requirements.  It was never needed.

2.0.1 (2023-07-11)
------------------

Documentation
^^^^^^^^^^^^^

- Update docs to reflect that you need to use an ``nginx`` with ``http_auth_request_modele`` built in.

1.0.0 (2023-07-07)
------------------

Enhancements
^^^^^^^^^^^^

- First release of the project
