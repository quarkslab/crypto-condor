"""Module for test commands."""

import typer

from crypto_condor.cli import run, verify

_test_help = """Test an implementation of a cryptographic primitive.

The `test` command provides two subcommands to test implementations: [red]wrapper[/] and
[blue]output[/]."""

app = typer.Typer(help=_test_help, no_args_is_help=True)


app.add_typer(run.app, name="wrapper")
app.add_typer(verify.app, name="output")
