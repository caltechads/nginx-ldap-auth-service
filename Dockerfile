FROM python:3.11.3-alpine3.17

USER root

ENV LC_ALL=en_US.utf8 LANG=en_US.utf8 PYCURL_SSL_LIBRARY=nss

RUN apk update && \
    apk upgrade && \
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
    rm -rf $(pip cache dir)

USER sidecar

EXPOSE 8888
CMD ["gunicorn", "--ssl-version", "2", "--config", "/app/nginx_ldap_auth/gunicorn_config.py", "nginx_ldap_auth.app.main:app"]
