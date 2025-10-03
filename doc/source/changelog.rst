CHANGELOG
=========

2.2.0 (2025-10-03)
------------------

Enhancements
^^^^^^^^^^^^

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
