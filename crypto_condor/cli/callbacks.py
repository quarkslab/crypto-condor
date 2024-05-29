"""Callbacks module.

It includes functions used as callbacks by CLI commands. This allows to validate
inputs, normalize them, or simply calling some functions before the rest of the
command.
"""

from importlib import metadata, resources

import typer
from rich.table import Table

from crypto_condor.primitives import TestU01
from crypto_condor.primitives.common import Console

console = Console()


def print_version(ver: bool):
    """Prints the current version and exits.

    Args:
        ver: True if the corresponding option was used.
    """
    if not ver:
        return
    console.print(f"crypto-condor version {metadata.version('crypto-condor')}")
    raise typer.Exit(0)


def list_languages(show: bool) -> None:
    """Lists the primitives and its available wrappers, and exits.

    Args:
        show: passed by Typer, True if the --list option was used.
    """
    if not show:
        return

    rsc = resources.files("crypto_condor")
    rsc_dir = rsc / "resources/wrappers/"

    primitives = dict()
    all_languages: set[str] = set()

    for primitive_dir in rsc_dir.iterdir():
        languages = {
            language_dir.name.capitalize()
            for language_dir in primitive_dir.iterdir()
            if "example" not in language_dir.name
        }
        primitives[primitive_dir.name.upper()] = languages
        all_languages = all_languages.union(languages)

    table = Table()

    table.add_column("Primitives")
    for language in all_languages:
        table.add_column(language, justify="center")

    for primitive, langs in primitives.items():
        row = [primitive]
        for language in all_languages:
            if language in langs:
                row.append("[green]✓")
            else:
                row.append("✕")
        table.add_row(*row)

    console.print(table)
    raise typer.Exit(0)


# ------------------------------ TestU01 -------------------------------------


def print_testu01_install_dir(show: bool):
    """Shows the install location of TestU01.

    Checks whether TestU01 seems installed or not.

    Args:
        show:
            Passed by Typer. If True, displays the location and quits, otherwise
            just returns.
    """
    if not show:
        return

    t_dir = TestU01.get_testu01_dir()

    # Path of the NIST battery executable.
    nist = t_dir / "examples/nist"

    if t_dir.is_dir() and nist.is_file():
        console.print(f"TestU01 is installed at {str(t_dir)}")
    else:  # pragma: no cover (requires removing TestU01 before)
        console.print(
            f"TestU01 is not installed but its location would be {str(t_dir)}"
        )

    raise typer.Exit()
