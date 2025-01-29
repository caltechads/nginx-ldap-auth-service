import os
import pprint

import click
import uvicorn

from ..settings import Settings
from .cli import cli

settings = Settings()


@cli.command("settings", short_help="Print our application settings.")
def print_settings():
    """
    Print our settings to stdout.  This should be the completely evaluated
    settings including those imported from any environment variable.
    """
    pp = pprint.PrettyPrinter(indent=2)
    pp.pprint(settings.model_dump())


@cli.command("start", short_help="Start the nginx_ldap_auth service.")
@click.option(
    "--host",
    "-h",
    default=lambda: os.environ.get("HOSTNAME", "0.0.0.0"),  # noqa: S104
    help="The host to listen on.",
)
@click.option(
    "--port",
    "-p",
    default=lambda: os.environ.get("PORT", 8888),
    type=int,
    help="The port to listen on.",
)
@click.option(
    "--reload/--no-reload",
    "-r",
    default=lambda: os.environ.get("RELOAD", False),
    type=bool,
    help="Reload the server on code changes.",
)
@click.option(
    "--keyfile",
    "-k",
    default=lambda: os.environ.get("SSL_KEYFILE", "/certs/server.key"),
    type=click.Path(exists=True, dir_okay=False),
    help="The path to the SSL key file.",
)
@click.option(
    "--certfile",
    "-c",
    default=lambda: os.environ.get("SSL_CERTFILE", "/certs/server.crt"),
    type=click.Path(exists=True, dir_okay=False),
    help="The path to the SSL certificate file.",
)
@click.option(
    "--workers",
    "-w",
    default=lambda: os.environ.get("WORKERS", 1),
    type=int,
    help="The number of worker processes to spawn.",
)
@click.option(
    "--env-file",
    default=None,
    type=click.Path(exists=True, dir_okay=False),
    help="The path to the environment file to load.",
)
def start(**kwargs):
    """
    Start the nginx_ldap_auth service.
    """
    uvicorn_kwargs = {
        "host": kwargs["host"],
        "port": kwargs["port"],
        "reload": kwargs["reload"],
        "ssl_keyfile": kwargs["keyfile"],
        "ssl_certfile": kwargs["certfile"],
        "workers": kwargs["workers"],
        "ssl_version": 2,
    }
    if kwargs["env_file"]:
        uvicorn_kwargs["env_file"] = kwargs["env_file"]
    uvicorn.run("nginx_ldap_auth.app.main:app", **uvicorn_kwargs)
