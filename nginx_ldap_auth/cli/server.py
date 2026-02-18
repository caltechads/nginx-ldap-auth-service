import os
import pprint

import click
import uvicorn

from ..settings import Settings
from .cli import cli

settings = Settings()


def ssl_required() -> bool:
    """
    Check if SSL/TLS is required by our configuration.

    - SSL is enabled by default.
    - SSL is only disabled when the :envvar:`INSECURE` environment variable is
      set to True.

    Returns:
        True if SSL/TLS is enabled, False otherwise.

    """
    return not settings.insecure


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
    default=lambda: int(os.environ.get("PORT", "8888")),
    type=int,
    help="The port to listen on.",
)
@click.option(
    "--reload/--no-reload",
    "-r",
    default=lambda: os.environ.get("RELOAD", "False") == "True",
    type=bool,
    help="Reload the server on code changes.",
)
@click.option(
    "--insecure",
    default=settings.insecure,
    type=bool,
    help="If the server should run over HTTP instead of HTTPS.",
)
@click.option(
    "--keyfile",
    "-k",
    default=lambda: os.environ.get("SSL_KEYFILE", "/certs/server.key"),
    type=click.Path(exists=ssl_required(), dir_okay=False),
    help="The path to the SSL key file.",
)
@click.option(
    "--certfile",
    "-c",
    default=lambda: os.environ.get("SSL_CERTFILE", "/certs/server.crt"),
    type=click.Path(exists=ssl_required(), dir_okay=False),
    help="The path to the SSL certificate file.",
)
@click.option(
    "--workers",
    "-w",
    default=lambda: int(os.environ.get("WORKERS", "1")),
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
        "workers": kwargs["workers"],
    }
    if not kwargs["insecure"]:
        # adding in SSL settings results in `uvicorn` running over HTTPS
        # the SSL settings will be ignored when insecure mode is enabled
        ssl_kwargs = {
            "ssl_keyfile": kwargs["keyfile"],
            "ssl_certfile": kwargs["certfile"],
            "ssl_version": 2,
        }
        uvicorn_kwargs |= ssl_kwargs
    if kwargs["env_file"]:
        uvicorn_kwargs["env_file"] = kwargs["env_file"]
    uvicorn.run("nginx_ldap_auth.app.main:app", **uvicorn_kwargs)
