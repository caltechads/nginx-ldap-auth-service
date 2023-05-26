import asyncio
import multiprocessing
import os
import pprint

from aiohttp import web
import click

from ..app.main import app_factory
from ..app.logging import AccessCaltechAccessLogger
from ..app.models import ServerStatus
from ..logging import logger
from ..settings import Settings

from .cli import cli


@cli.command('settings', short_help="Print our application settings.")
def settings():
    """
    Print our settings to stdout.  This should be the completely evaluated settings including
    those imported from any environment variable.
    """
    pp = pprint.PrettyPrinter(indent=2)
    pp.pprint(Settings().dict())


@cli.command('setup', short_help="Write an nginx config that starts the correct # of aiohttp servers for our # cpus")
@click.option('--nginx-path', default="/etc/nginx/nginx.conf",
              help="Path to the nginx.conf file to create.  Default: /etc/nginx/nginx.conf")
@click.option('--supervisord-path', default="/etc/supervisord.conf",
              help="Path to the nginx.conf file to create.  Default: /etc/supervisord.conf")
@click.pass_context
def setup(ctx, nginx_path, supervisord_path):
    """
    Write nginx and supervisord configs that start and use the correct # of aiohttp servers for our number of cpus.
    aiohttp is single threaded, so to maximize our usage of the box it runs on, we should start one per CPU core.

    This command creates an appropriate `/etc/nginx.conf` and `/etc/supervisord.conf` that does that.

    If the environment variable ``DEVELOPMENT` is set to "``True``", use only one core no matter how many
    cores are available.

    If the environment variable ``AIOHTTP_SERVER_COUNT`` is set to an integer, use that many cores unless that exceeds
    the actual number of cores in the system, else use the max cores.
    """
    development_mode = os.environ.get('DEVELOPMENT', 'False') == 'True'
    servers = int(os.environ.get('AIOHTTP_SERVER_COUNT', -1))
    if development_mode:
        ncores = 1
    else:
        ncores = multiprocessing.cpu_count()
        if servers > 0:
            ncores = servers if servers <= ncores else ncores
    logger.info('access-loadapp-cli.setup', development_mode=development_mode, ncores=ncores)

    with open(nginx_path, 'w+', encoding='utf-8') as f:
        nginx_conf = ctx.obj['env'].get_template('nginx.conf.tpl')
        f.write(nginx_conf.render(ncores=ncores, development=development_mode))

    with open(supervisord_path, 'w+', encoding='utf-8') as f:
        supervisord_conf = ctx.obj['env'].get_template('supervisord.conf.tpl')
        f.write(supervisord_conf.render(ncores=ncores, development=development_mode))


@cli.group(short_help="Manage access_loadapp servers")
def server():
    pass


@server.command('start', short_help="Start an access_loadapp aiohttp server in the foreground.")
@click.option('--path', default=None, help="Path to the unix socket that with which nginx will communicate.")
def server_start(path):
    """
    Start an aiohttp access_loadapp server.
    """
    if not path:
        path = os.path.join('/tmp', 'access_loadapp.sock')
    web.run_app(
        app_factory(),
        path=path,
        access_log_class=AccessCaltechAccessLogger,
        access_log_format='%a - %u "%t" "%r" %s %b "%{Referer}i" "%{User-Agent}i"'
    )


@server.command('hostinfo', short_help="Print the ServerStatus info for this host.")
def server_status():
    """
    Print the ServerStatus info for this host.
    """
    info = asyncio.run(ServerStatus.new(None))
    pp = pprint.PrettyPrinter(indent=2)
    pp.pprint(info.dict())