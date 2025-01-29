#!/usr/bin/env python
import sys

import click

import nginx_ldap_auth


@click.group(invoke_without_command=True)
@click.option(
    "--version/--no-version",
    "-v",
    default=False,
    help="Print the current version and exit.",
)
@click.pass_context
def cli(_, version: bool) -> None:
    """
    The nginx_ldap_auth command line interface.
    """
    if version:
        print(nginx_ldap_auth.__version__)
        sys.exit(0)
