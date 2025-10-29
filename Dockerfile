FROM python:3.13-alpine3.21 AS build

ENV UV_PROJECT_ENVIRONMENT=/ve \
    UV_COMPILE_BYTECODE=1      \
    UV_LINK_MODE=copy          \
    UV_PYTHON_DOWNLOADS=never

RUN apk update && \
    apk upgrade && \
    apk add \
        gcc \
        musl-dev \
        libffi-dev \
        openssl \
        openssl-dev \
        python3-dev \
        libxml2-dev \
        libxslt-dev \
        openldap-dev

RUN --mount=type=cache,target=/uv-cache \
    --mount=from=ghcr.io/astral-sh/uv,source=/uv,target=/bin/uv \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    uv --cache-dir=/uv-cache sync --frozen --no-install-project

FROM python:3.13-alpine3.21

ENV HISTCONTROL=ignorespace:ignoredups  \
    PATH=/ve/bin:/app:$PATH             \
    PYCURL_SSL_LIBRARY=nss              \
    UV_PROJECT_ENVIRONMENT=/ve          \
    UV_LINK_MODE=copy                   \
    VIRTUAL_ENV=/ve

RUN apk update && \
    apk upgrade && \
    apk add \
        openssl \
        openldap \
    && \
    # Add the user under which we will run.
    adduser -H -D app && \
    # Generate a self-signed SSL cert for nginx to use.
    mkdir -p /certs && \
    openssl req -x509 -nodes \
      -subj "/C=US/ST=CA/O=Caltech/CN=localhost.localdomain" \
      # 10 years
      -days 3650 \
      -newkey rsa:2048 \
      -keyout /certs/server.key \
      -out /certs/server.crt && \
    chown app:app /certs/* && \
    pip install --upgrade uv pip setuptools

COPY --from=build --chown=app:app /ve /ve
ENV PATH=/ve/bin:$PATH PYTHONPATH=/app

COPY . /app
WORKDIR /app

RUN --mount=type=cache,target=/uv-cache \
    uv --cache-dir=/uv-cache sync --frozen

USER app

EXPOSE 8888

CMD ["nginx-ldap-auth", "start"]
