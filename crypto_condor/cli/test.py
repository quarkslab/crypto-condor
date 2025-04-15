"""Module for test commands."""

import logging
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich import box
from rich.table import Table

from crypto_condor import harness
from crypto_condor.cli import run, verify
from crypto_condor.primitives.common import Console

logger = logging.getLogger(__name__)
console = Console()

_test_help = """Test an implementation of a cryptographic primitive.

The `test` command provides two subcommands to test implementations: [red]wrapper[/] and [blue]output[/].
"""  # noqa: E501

app = typer.Typer(help=_test_help, no_args_is_help=True)


app.add_typer(run.app, name="wrapper")
app.add_typer(verify.app, name="output")


def _list_functions(path: Path, included: list[str] | None, excluded: list[str] | None):
    if included is None:
        included = []
    if excluded is None:
        excluded = []
    functions = harness.list_functions(path, included, excluded)

    table = Table(box=box.SIMPLE)
    table.add_column("[green1]Included[/] functions found")
    if len(functions["included"]) == 0:
        table.add_row("[red1]No functions found[/]")
    else:
        for func in sorted(functions["included"]):
            table.add_row(func)
    console.print(table)

    if excluded:
        table = Table(box=box.SIMPLE)
        table.add_column("[yellow1]Excluded[/] functions found")
        if len(functions["excluded"]) == 0:
            table.add_row("No functions found")
        else:
            for func in sorted(functions["excluded"]):
                table.add_row(func)
        console.print(table)

    table = Table(box=box.SIMPLE)
    table.add_column("Other functions found")
    if len(functions["other"]) == 0:
        table.add_row("No functions found")
    else:
        for func in sorted(functions["other"]):
            table.add_row(func)
    console.print(table)

    diff = set(included).difference(set(functions["included"]))
    if len(diff) > 0:
        table = Table(box=box.SIMPLE)
        table.add_column("[green1]Included[/] functions [red1]not[/] found")
        for func in sorted(diff):
            table.add_row(func)
        console.print(table)


_hook_help = """Test a shared library harness.

Load a shared library and test exposed functions that match crypto-condor's API:
[cyan]https://quarkslab.github.io/crypto-condor/latest/harness-api/index.html[/]

By default, [bold]all functions[/] matching the naming convention and API are tested.

When using --include, only functions explicitly included are be tested (allow list).

When using --exclude, all functions are tested except those excluded (deny list).

The --include and --exclude options are exclusive.

To list all functions found in a harness, use --list.
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
    compliance: Annotated[
        bool,
        typer.Option(
            "--compliance/--no-compliance", help="Use compliance test vectors."
        ),
    ] = True,
    resilience: Annotated[
        bool,
        typer.Option(
            "--resilience/--no-resilience", help="Use resilience test vectors."
        ),
    ] = False,
    no_save: Annotated[
        bool, typer.Option("--no-save", help="Do not prompt to save results.")
    ] = False,
    list_functions: Annotated[
        bool, typer.Option("--list", help="List all the functions found in a harness.")
    ] = False,
):
    """Tests a shared library hook.

    Args:
        lib:
            Unvalidated path of the shared library to test.

    Keyword Args:
        included:
            List of functions to include, allow-list style.
        excluded:
            List of functions to exclude, deny-list style.
        compliance:
            Whether to use compliance test vectors.
        resilience:
            Whether to use resilience test vectors.
        no_save:
            If True, no results are saved and the user is not prompted.
        list_functions:
            If True, lists all functions in the harness and exits.
    """
    if list_functions:
        _list_functions(Path(lib), included, excluded)
        raise typer.Exit(0)

    if included and excluded:
        console.print("Using both --include and --exclude is not allowed")
        raise typer.Exit(1)

    try:
        results = harness.test_harness(
            Path(lib), included, excluded, compliance, resilience
        )
    except (ValueError, FileNotFoundError) as error:
        logger.error(str(error))
        logger.debug("Exception caught while testing harness", exc_info=True)
        raise typer.Exit(1) from error

    if console.process_results(results, no_save=no_save):
        raise typer.Exit(0)
    else:
        raise typer.Exit(1)
