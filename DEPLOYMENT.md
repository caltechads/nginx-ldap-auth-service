# LDAP Helper Deployment Guide (Podman Quadlet)

This guide defines deployable runtime contract for `nginx-ldap-auth-service` in SPNEGO header-auth flow.

## Deployment Shape

- Same host as auth gateway
- Same Podman network as auth gateway
- Different container IPs
- Gateway reaches helper by service DNS/container name on Podman network
- Helper listens on `0.0.0.0:8888`

## Security Baseline

- LDAPS certificate validation enabled by default (`LDAP_VALIDATE_CERT=true`)
- AD CA certificate mounted at runtime (do not bake customer CA into image)
- Effective authorization filter is required
- Missing effective authorization filter fails closed (`500`)
- Header-auth trusted header is `X-Ldap-User`
- Default identity model for SPNEGO flow:
  - NGINX sends full UPN (for example `alice@SAMDOM.EXAMPLE.COM`)
  - LDAP user lookup filter uses `userPrincipalName`

## Environment Variables

Required:

| Variable | Example | Purpose |
| --- | --- | --- |
| `LDAP_URI` | `ldaps://ad01.corp.example.com:636` | LDAP/AD endpoint |
| `LDAP_BINDDN` | `CN=ldap-auth-svc,CN=Users,DC=corp,DC=example,DC=com` | Service bind DN |
| `LDAP_PASSWORD` | `<secret>` | Service bind password |
| `LDAP_BASEDN` | `DC=corp,DC=example,DC=com` | Base DN for searches |
| `SECRET_KEY` | `<secret>` | Session signing key |
| `CSRF_SECRET_KEY` | `<secret>` | CSRF signing key |
| `LDAP_AUTHORIZATION_FILTER` | `(&(userPrincipalName={username})(memberOf=CN=Developers,CN=Users,DC=corp,DC=example,DC=com))` | Baseline authorization policy |
| `LDAP_GET_USER_FILTER` | `(userPrincipalName={username})` | User lookup filter for full UPN flow |

Recommended:

| Variable | Example | Purpose |
| --- | --- | --- |
| `HEADER_AUTH_ENABLED` | `true` | Enable `/check-header` flow |
| `LDAP_TRUSTED_USER_HEADER` | `X-Ldap-User` | Trusted upstream user header |
| `ALLOW_AUTHORIZATION_FILTER_HEADER` | `true` | Allow per-route filter override from gateway |
| `LDAP_VALIDATE_CERT` | `true` | Validate LDAPS certificate |
| `LDAP_CA_CERT_DIR` | `/etc/ldap/ca` | Directory holding mounted CA file |
| `LDAP_CA_CERT_NAME` | `customer-ad-ca.pem` | CA file name inside mounted directory |
| `HOST` | `0.0.0.0` | Bind interface |
| `PORT` | `8888` | Service port |
| `LOG_LEVEL` | `INFO` | Log level |
| `LOG_TYPE` | `text` | Log output format |
| `HEADER_AUTH_CACHE_TTL` | `300` | Header-auth cache TTL in seconds |

Optional Redis cache:

| Variable | Example | Purpose |
| --- | --- | --- |
| `SESSION_BACKEND` | `redis` | Redis-backed cache/session backend |
| `REDIS_URL` | `redis://redis:6379/0` | Redis DSN |

## Required Mounts

- Env file (for secrets and runtime config), for example `/etc/ldap-auth/ldap-auth.env`
- AD CA file mount, for example:
  - host path: `/etc/pki/customer-ad-ca.pem`
  - container path: `/etc/ldap/ca/customer-ad-ca.pem:ro`

## Podman Quadlet Examples

Recommended (Redis-enabled) deployment:

`/etc/containers/systemd/redis-ldap-auth.container`

```ini
[Unit]
Description=Redis for LDAP auth cache

[Container]
Image=docker.io/library/redis:7-alpine
ContainerName=redis-ldap-auth
Network=authnet.network
PublishPort=127.0.0.1:6379:6379

[Service]
Restart=always

[Install]
WantedBy=multi-user.target
```

`/etc/containers/systemd/ldap-auth.container`

```ini
[Unit]
Description=LDAP auth helper
After=redis-ldap-auth.service
Wants=redis-ldap-auth.service

[Container]
Image=ghcr.io/your-org/nginx-ldap-auth-service:<tag>
ContainerName=ldap-auth
Network=authnet.network
EnvironmentFile=/etc/ldap-auth/ldap-auth.env
Volume=/etc/pki/customer-ad-ca.pem:/etc/ldap/ca/customer-ad-ca.pem:ro
PublishPort=127.0.0.1:8888:8888
HealthCmd=/usr/bin/curl -fsS http://127.0.0.1:8888/status || exit 1
HealthInterval=30s
HealthTimeout=5s
HealthRetries=3
HealthStartPeriod=20s

[Service]
Restart=always

[Install]
WantedBy=multi-user.target
```

Example network quadlet:

`/etc/containers/systemd/authnet.network`

```ini
[Network]
NetworkName=authnet
```

Apply and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now authnet-network.service
sudo systemctl enable --now redis-ldap-auth.service
sudo systemctl enable --now ldap-auth.service
```

## Health and Smoke Checks

Liveness endpoint:

```bash
curl -fsS http://127.0.0.1:8888/status
```

LDAP reachability endpoint:

```bash
curl -fsS http://127.0.0.1:8888/status/ldap
```

Header-auth checks:

```bash
# 401: missing trusted user header
curl -i http://127.0.0.1:8888/check-header

# 200/403 depending on group membership
curl -i -H 'X-Ldap-User: alice@CORP.EXAMPLE.COM' \
  -H 'X-Authorization-Filter: (&(userPrincipalName={username})(memberOf=CN=Developers,CN=Users,DC=corp,DC=example,DC=com))' \
  http://127.0.0.1:8888/check-header
```

## Redis Degraded Mode

- Service works without Redis (in-memory fallback)
- Expect higher LDAP load and less cache protection when Redis is unavailable
- Recommended production profile keeps Redis enabled

## Gateway Header Security Contract

Gateway configuration must prevent header spoofing from clients.

- Do not pass client request headers through to helper
- Explicitly set trusted identity header (`X-Ldap-User`) in gateway
- Explicitly set or clear `X-Authorization-Filter` per location

Recommended pattern in gateway subrequest location:

```nginx
proxy_pass_request_headers off;
proxy_pass_request_body off;
proxy_set_header Content-Length "";
proxy_set_header X-Ldap-User $remote_user;
proxy_set_header X-Authorization-Filter "(&(userPrincipalName={username})(memberOf=CN=Developers,CN=Users,DC=corp,DC=example,DC=com))";
```
