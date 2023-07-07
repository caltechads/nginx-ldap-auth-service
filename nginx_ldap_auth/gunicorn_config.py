import environ
import json
import multiprocessing
from typing import Optional

env = environ.Env()

# general
bind: str = f'{env.str("HOSTNAME", default="0.0.0.0")}:{env.int("PORT", default=8888)}'
_workers: str = env.str('WORKERS', default='1')
if _workers == 'auto':
    workers: int = 2 * multiprocessing.cpu_count() + 1
else:
    workers = int(_workers)
worker_class: str = 'uvicorn.workers.UvicornWorker'
daemon: bool = env.bool('GUNICORN_DAEMON', default=False)
timeout = env.int('LDAP_TIMEOUT', default=15) + 2
worker_tmp_dir = '/tmp'

# requires futures module for threads > 1
threads: int = 1

reload: bool = env.bool('GUNICORN_RELOAD', default=False)

keyfile: str = '/certs/localhost.key'
certfile: str = '/certs/localhost.crt'

# Logging.
accesslog: str = '-'
errorlog: str = '-'
access_log_format: str = json.dumps(
    {
        'type': 'access',
        'program': 'gunicorn',
        'time_local': r'%(t)s',
        'remote_addr': r'%({x-forwarded-for}i)s',
        'remote_user': r'%(u)s',
        'request': r'%(r)s',
        'status': r'%(s)s',
        'method': r'%(m)s',
        'path': r'%(U)s',
        'query_string': r'%(q)s',
        'response_length': r'%(B)s',
        'request_time': r'%(T)s',
        'http_referer': r'%(f)s',
        'http_user_agent': r'%(a)s'
    }
)
loglevel: str = env.str('LOG_LEVEL', default='INFO')

_host: Optional[str] = env('STATSD_HOST', default=None)
_port: int = env.int('STATSD_PORT', default=8125)
statsd_host: Optional[str] = f'{_host}:{_port}' if (_host and _port) else None
statsd_prefix: Optional[str] = env('STATSD_PREFIX', default=None)
