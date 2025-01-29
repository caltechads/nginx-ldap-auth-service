FROM python:3.11.11-alpine3.21 AS build

# This part builds the virtual environment and installs the system dependencies
# needed to do so.

ENV UV_PROJECT_ENVIRONMENT=/ve

ENV LC_ALL=en_US.utf8 LANG=en_US.utf8 PYCURL_SSL_LIBRARY=nss

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
        openldap-dev \
    && \
    /usr/local/bin/pip install --upgrade uv setuptools pip wheel

COPY pyproject.toml /_lock/
COPY uv.lock /_lock/
RUN cd /_lock && \
    uv sync --frozen --no-dev

FROM python:3.11.11-alpine3.21

ENV HISTCONTROL=ignorespace:ignoredups  \
    IPYTHONDIR=/etc/ipython             \
    LANG=en_US.UTF-8                    \
    LANGUAGE=en_US.UTF-8                \
    LC_ALL=en_US.UTF-8                  \
    # Disable the pip cache to reduce layer size.
    PIP_NO_CACHE_DIR=1                  \
    PYCURL_SSL_LIBRARY=nss              \
    # This env var overrides other system timezone settings.
    TZ=America/Los_Angeles              \
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
      -days 3650 \
      -newkey rsa:2048 \
      -keyout /certs/server.key \
      -out /certs/server.crt && \
    chown app:app /certs/* && \
    pip install --upgrade setuptools pip

COPY --from=build --chown=app:app /ve /ve
ENV PATH=/ve/bin:$PATH PYTHONPATH=/app

#RUN pip uninstall -y setuptools

COPY . /app
WORKDIR /app

USER app

EXPOSE 8888

CMD ["nginx-ldap-auth", "start"]
