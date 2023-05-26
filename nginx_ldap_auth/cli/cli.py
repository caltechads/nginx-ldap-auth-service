#!/usr/bin/env python
import sys

import click
from jinja2 import Environment, FileSystemLoader

import access_loadapp


@click.group(invoke_without_command=True)
@click.option('--version/--no-version', '-v', default=False, help="Print the current version and exit.")
@click.pass_context
def cli(ctx, version):
    """
    access_loadapp command line interface.
    """
    ctx.obj['env'] = Environment(
        loader=FileSystemLoader('/app/etc/templates'),
        autoescape=False,
        extensions=['jinja2.ext.do']
    )

    if version:
        print(access_loadapp.__version__)
        sys.exit(0)
