
Features
========

User authentication
-------------------

- Login form and page
- Login sessions backed by Redis
  Users are automatically logged out after one hour of idle time.
- Integration with the [nginx_http_auth_request_module](http://nginx.org/en/docs/http/ngx_http_auth_request_module.html)

Other features
--------------
- Implemented in [FastAPI](https://fastapi.tiangolo.com/) for speed and
  connection management.