# nginx-ldap-auth-service

`nginx-ldap-auth-service` is a high-performance authentication daemon built with [FastAPI](https://fastapi.tiangolo.com/). It provides an authentication bridge between [nginx](https://nginx.org/) and LDAP or Active Directory servers, including support for Duo MFA.

It works in conjunction with nginx's [ngx_http_auth_request_module](http://nginx.org/en/docs/http/ngx_http_auth_request_module.html) to provide a seamless login experience for your web applications.

## Features

- **LDAP/Active Directory Integration**: Authenticate users against any LDAP-compliant server or Microsoft Active Directory.
- **FastAPI Powered**: High performance, asynchronous connection management, and modern implementation.
- **Login Form & Session Management**: Built-in login form and session handling.
- **Duo MFA Support**: Optional Duo Multi-Factor Authentication workflow.
- **Flexible Session Backends**: Support for in-memory or Redis-based sessions for high availability.
- **Authorization Filters**: Restrict access based on LDAP search filters (e.g., group membership).
- **Docker Ready**: Easily deployable as a sidecar container.
- **Monitoring Endpoints**: Built-in `/status` and `/status/ldap` health checks.

## Installation

### via pip

```bash
pip install nginx-ldap-auth-service
```

### via uv

```bash
uv tool install nginx-ldap-auth-service
```

### via pipx

```bash
pipx install nginx-ldap-auth-service
```

### via Docker

```bash
docker pull caltechads/nginx-ldap-auth-service:latest
```

## Quick Start (Docker Compose)

Create a `docker-compose.yml` file:

```yaml
services:
  nginx-ldap-auth-service:
    image: caltechads/nginx-ldap-auth-service:latest
    environment:
      - LDAP_URI=ldap://ldap.example.com
      - LDAP_BASEDN=dc=example,dc=com
      - LDAP_BINDDN=cn=admin,dc=example,dc=com
      - LDAP_PASSWORD=secret
      - SECRET_KEY=your-session-secret
      - CSRF_SECRET_KEY=your-csrf-secret
    ports:
      - "8888:8888"
```

Run with:

```bash
docker-compose up -d
```

## Configuration

The service can be configured via environment variables, command-line arguments, or Nginx headers.

### Required Environment Variables

| Variable | Description |
| --- | --- |
| `LDAP_URI` | URL of the LDAP server (e.g., `ldap://localhost`) |
| `LDAP_BINDDN` | DN of a privileged user for searches |
| `LDAP_PASSWORD` | Password for the `LDAP_BINDDN` user |
| `LDAP_BASEDN` | Base DN for user searches |
| `SECRET_KEY` | Secret key for session encryption |
| `CSRF_SECRET_KEY` | Secret key for CSRF protection |

### Important Optional Variables

- `DUO_ENABLED`: Set to `True` to enable Duo MFA (Note that you must also define all the DUO_* configs also)
- `SESSION_BACKEND`: `memory` (default) or `redis`.
- `LDAP_AUTHORIZATION_FILTER`: LDAP filter to restrict access.
- `COOKIE_NAME`: Name of the session cookie (default: `nginxauth`).

For a full list of configuration options, see the [Configuration Documentation](https://nginx-ldap-auth-service.readthedocs.io/en/latest/configuration.html).

## Nginx Integration

To use the service with Nginx, configure your `location` blocks to use `auth_request`:

```nginx
location / {
    auth_request /check-auth;
    error_page 401 =200 /auth/login?service=$request_uri;
    # ... your application config ...
}

location /auth {
    proxy_pass http://nginx-ldap-auth-service:8888/auth;
    proxy_set_header X-Cookie-Name "nginxauth";
    proxy_set_header X-Cookie-Domain "localhost";
    proxy_set_header X-Proto-Scheme $scheme;
    proxy_set_header Host $host;
    proxy_set_header Cookie $http_cookie;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for
}

location /check-auth {
    internal;
    proxy_pass http://nginx-ldap-auth-service:8888/check;
    proxy_pass_request_headers off;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_ignore_headers "Set-Cookie";
    proxy_hide_header "Set-Cookie";
    proxy_cache auth_cache;
    proxy_cache_valid 200 10m;
    proxy_set_header X-Cookie-Name "nginxauth";
    proxy_set_header Cookie nginxauth=$cookie_nginxauth;
    proxy_set_header X-Cookie-Domain "localhost";
    proxy_cache_key "$http_authorization$cookie_nginxauth";
}
```

For detailed Nginx configuration examples, including caching and Duo MFA headers, see the [Nginx Configuration Guide](https://nginx-ldap-auth-service.readthedocs.io/en/latest/nginx.html).

## Documentation

The full documentation is available at [https://nginx-ldap-auth-service.readthedocs.io](https://nginx-ldap-auth-service.readthedocs.io).

## License

This project is licensed under the terms of the [LICENSE.txt](LICENSE.txt) file.
