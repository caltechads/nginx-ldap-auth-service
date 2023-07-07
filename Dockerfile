FROM python:3.11.3-alpine3.17

USER root

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
    # Add the user under which we will run.
    adduser -H -D sidecar && \
    # Make our virtualenv
    python3 -m venv /ve

ENV PATH /ve/bin:$PATH

RUN pip install --upgrade pip wheel && \
    rm -rf $(pip cache dir)

COPY . /app
WORKDIR /app

RUN pip install -e . && \
    rm -rf $(pip cache dir) && \
    mkdir /certs && \
    openssl req -x509 -nodes -days 3650 \
      -subj  "/C=US/ST=CA/O=Caltech/CN=localhost.localdomain" \
      -newkey rsa:2048 -keyout /certs/localhost.key \
      -out /certs/localhost.crt && \
    chown -R sidecar /certs/*

USER sidecar

EXPOSE 8888
#CMD ["gunicorn", "--ssl-version", "2", "--config", "/app/nginx_ldap_auth/gunicorn_config.py", "nginx_ldap_auth.app.main:app"]
#CMD ["python", "/app/nginx_ldap_auth/server.py"]
CMD ["uvicorn", "--ssl-keyfile", "/certs/localhost.key", "--ssl-certfile", "/certs/localhost.crt", "--host", "0.0.0.0", "--port", "8888", "nginx_ldap_auth.app.main:app"]