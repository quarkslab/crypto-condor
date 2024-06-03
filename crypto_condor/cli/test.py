"""Module for test commands."""

from pathlib import Path
from typing import Annotated, Optional

import typer

from crypto_condor import harness
from crypto_condor.cli import run, verify
from crypto_condor.primitives.common import Console

console = Console()

_test_help = """Test an implementation of a cryptographic primitive.

The `test` command provides two subcommands to test implementations: [red]wrapper[/] and [blue]output[/].
"""  # noqa: E501

app = typer.Typer(help=_test_help, no_args_is_help=True)


app.add_typer(run.app, name="wrapper")
app.add_typer(verify.app, name="output")

_hook_help = """Test a shared library hook.

Load a shared library and test exposed functions that match crypto-condor's API.

When using --include, only functions included will be tested (allow list).

When using --exclude, all functions are tested except those excluded (deny list).

The --include and --exclude options are exclusive.
"""


@app.command("harness", help=_hook_help, no_args_is_help=True)
def test_harness(
    lib: Annotated[
        str,
        typer.Argument(
            help="The path to the shared library to test.",
            show_default=False,
            metavar="PATH",
        ),
    ],
    included: Annotated[
        Optional[list[str]], typer.Option("--include", "-i", help="Include a function.")
    ] = None,
    excluded: Annotated[
        Optional[list[str]], typer.Option("--exclude", "-e", help="Exclude a function.")
    ] = None,
):
    """Tests a shared library hook.

    Args:
        lib: Unvalidated path of the shared library to test.
        included: List of functions to include, allow-list style.
        excluded: List of functions to exclude, deny-list style.
    """
    if included and excluded:
        console.print("Using both --include and --exclude is not allowed")
        raise typer.Exit(1)

    results = harness.test_harness(Path(lib), included, excluded)
    if console.process_results(results):
        raise typer.Exit(0)
    else:
        raise typer.Exit(1)
