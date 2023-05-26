# nginx-ldap-auth-service

`nginx-ldap-auth-service` provides a method of authenticating users who request
protected resources from servers proxied by [nginx](https://www.nginx.com/)
against an LDAP or Active Directory server.  It provides a daemon
(`nginx-ldap-auth`) that communicates with an LDAP or Active Directory server
to authenticate users with their username and password, as well as a login form
for actually allowing users to authenticate.

The `nginx-ldap-auth` server utilizes the `ngx_http_auth_request_module` to do
its work.  To see if your version of `nginx` has that installed, do:

```bash
$ nginx -V
nginx version: nginx/1.23.4
root@cb1533767dca:/# nginx -V
nginx version: nginx/1.23.4
built by gcc 10.2.1 20210110 (Debian 10.2.1-6)
built with OpenSSL 1.1.1n  15 Mar 2022
TLS SNI support enabled
configure arguments: --prefix=/etc/nginx --sbin-path=/usr/sbin/nginx --modules-path=/usr/lib/nginx/modules --conf-path=/etc/nginx/nginx.conf --error-log-path=/var/log/nginx/error.log --http-log-path=/var/log/nginx/access.log --pid-path=/var/run/nginx.pid --lock-path=/var/run/nginx.lock --http-client-body-temp-path=/var/cache/nginx/client_temp --http-proxy-temp-path=/var/cache/nginx/proxy_temp --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp --http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp --http-scgi-temp-path=/var/cache/nginx/scgi_temp --user=nginx --group=nginx --with-compat --with-file-aio --with-threads --with-http_addition_module --with-http_auth_request_module --with-http_dav_module --with-http_flv_module --with-http_gunzip_module --with-http_gzip_static_module --with-http_mp4_module --with-http_random_index_module --with-http_realip_module --with-http_secure_link_module --with-http_slice_module --with-http_ssl_module --with-http_stub_status_module --with-http_sub_module --with-http_v2_module --with-mail --with-mail_ssl_module --with-stream --with-stream_realip_module --with-stream_ssl_module --with-stream_ssl_preread_module --with-cc-opt='-g -O2 -ffile-prefix-map=/data/builder/debuild/nginx-1.23.4/debian/debuild-base/nginx-1.23.4=. -fstack-protector-strong -Wformat -Werror=format-security -Wp,-D_FORTIFY_SOURCE=2 -fPIC' --with-ld-opt='-Wl,-z,relro -Wl,-z,now -Wl,--as-needed -pie'
```

Look through the `configure arguments` for `--with-http_auth_request_module`.  If you see that,
you're all set to begin using `nginx-ldap-auth-service`