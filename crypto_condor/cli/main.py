"""Main CLI module."""

import logging
import shutil
from importlib import metadata, resources
from pathlib import Path
from typing import Annotated, Literal, Optional

import typer
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

import crypto_condor.cli.callbacks as callbacks
from crypto_condor.cli import test
from crypto_condor.cli.config import set_logging
from crypto_condor.constants import SUPPORTED_MODES, SUPPORTED_PRIMITIVES, Primitive
from crypto_condor.primitives.common import Console

# --------------------------- Module --------------------------------------------------
console = Console()
app = typer.Typer(
    rich_markup_mode="rich",
    no_args_is_help=True,
    context_settings={"max_content_width": console.width},
    pretty_exceptions_show_locals=False,
)
app.add_typer(test.app, name="test", rich_help_panel="Test implementations")

logger = logging.getLogger(__name__)


# --------------------------- Functions -----------------------------------------------
def _primitive_callback(ctx: typer.Context, value: str) -> str | None:
    """Returns a valid primitive for the given context.

    Args:
        ctx: The command's context.
        value: The user input.

    Returns:
        The name of a primitive that is supported by the context's command. The name is
        a valid value for :enum:`Primitive` but the conversion to enum is left to the
        caller to help mypy.
    """
    if ctx.resilient_parsing:  # pragma: no cover (auto-completion)
        return None
    name: Literal["method", "wrapper"]
    match ctx.command.name:
        case "method":
            name = "method"
        case "get-wrapper":
            name = "wrapper"
    choices = [str(p) for p in Primitive if SUPPORTED_MODES[p][name]]
    while value not in choices:
        if value not in SUPPORTED_PRIMITIVES:
            console.print(f"[yellow]{value}[/] is not supported.")
        elif name == "method":
            console.print(f"There is no method guide for [yellow]{value}[/].")
        else:
            console.print(f"There are no wrappers for [yellow]{value}[/].")
        value = Prompt.ask("Select a primitive", console=console, choices=choices)
    return value


# --------------------------- Common arguments ----------------------------------------

_primitive = typer.Argument(
    help=(
        "The primitive to get a file for."
        " To see the supported primitives use the [cyan]list[/] command."
    ),
    show_default=False,
)

# --------------------------- Commands ------------------------------------------------

_method_help = """Get a method guide of a primitive.

Method guides contain key information on the primitive, such as its parameters, as well as the corresponding rules and recommendations by the ANSSI.

Bear in mind that, while the guides are provided in Markdown format, it is [bold]recommended[/] to read them directly from the documentation, as the formatting is not optimised for the source file.
"""  # noqa: E501


def _method_autocomplete_primitive():  # pragma: no cover (auto-completion)
    return [str(p) for p in Primitive if SUPPORTED_MODES[p]["method"]]


@app.command("method", no_args_is_help=True, help=_method_help)
def method(
    primitive: Annotated[
        str,
        typer.Argument(
            help="The primitive to get a method guide of.",
            show_default=False,
            autocompletion=_method_autocomplete_primitive,
            callback=_primitive_callback,
        ),
    ],
    out: Annotated[
        Optional[Path],
        typer.Option(help="Output file, defaults to primitive.md.", show_default=False),
    ] = None,
):
    """Command to get a method guide in Markdown.

    Args:
        primitive: The method guide to get.
        out: Where to save the guide.
    """
    prim = Primitive(primitive)
    method_dir = resources.files("crypto_condor") / "resources/guides"
    method_file = method_dir / f"{str(prim)}.md"
    if out is None:
        out = Path(f"{str(prim)}.md")
    try:
        shutil.copyfile(str(method_file), out)
        console.print(f"Saved {str(prim)} guide to [cyan]{str(out)}[/]")
    except OSError as error:  # pragma: no cover (need to trigger error)
        logger.error(error)
        raise typer.Exit(1) from error


@app.command("list")
def list_command():
    """List the currently supported primitives."""
    desc = "method      : Method guides on primitives.\n"
    desc += "test wrapper: Test an implementation with test vectors using a wrapper.\n"
    desc += "test output : Test the output of an implementation.\n"
    desc += "test harness: Test an implementation with test vectors using a harness."
    console.print(Panel(desc, title="Test modes"))

    table = Table()
    table.add_column("Supported primitives")
    # table.add_column("audit", justify="center")
    table.add_column("method", justify="center")
    table.add_column("test wrapper", justify="center")
    table.add_column("test output", justify="center")
    table.add_column("test harness", justify="center")

    _yes = "[green]Y[/]"
    _no = "-"
    for primitive, modes in SUPPORTED_MODES.items():
        # a = "[green]Y" if value["audit"] else "[red]N"
        m = _yes if modes["method"] else _no
        o = _yes if modes["output"] else _no
        w = _yes if modes["wrapper"] else _no
        h = _yes if modes["harness"] else _no
        table.add_row(primitive, m, w, o, h)
    console.print(table)
    raise typer.Exit()


_wrap_help = """Get a wrapper to test an implementation.

Wrappers are small programs that the user fills to call the implementations they want to test. crypto-condor then runs the wrapper to pass test vectors to the implementation.

This commands creates a template for a given primitive and programming language. Most wrappers are written in Python, with some in C. Use the --list option to show available languages.

The names of the files should not be changed as they are currently hard-coded in the tool. To override this behaviour use --force.
"""  # noqa: E501


def _wrap_autocomplete_primitive():  # pragma: no cover (auto-completion)
    return [p for p in SUPPORTED_MODES if SUPPORTED_MODES[p]["wrapper"]]


@app.command(
    name="get-wrapper",
    help=_wrap_help,
    no_args_is_help=True,
    rich_help_panel="Test implementations",
)
def wrap(
    primitive: Annotated[
        str,
        typer.Argument(
            help="The primitive to test.",
            callback=_primitive_callback,
            autocompletion=_wrap_autocomplete_primitive,
            show_default=False,
        ),
    ],
    directory: Annotated[
        Optional[str],
        typer.Option(
            "-d",
            "--dir",
            help=(
                "The directory to where the template is copied,"
                " created if it doesn't exist."
                " If unspecified, the current working directory is used."
            ),
            show_default=False,
        ),
    ] = None,
    language: Annotated[
        str,
        typer.Option(
            "--language",
            "-l",
            help="The language of the wrapper.",
        ),
    ] = "",
    show_languages: Annotated[
        bool,
        typer.Option(
            "--list",
            help="Show the available wrappers for all primitives.",
            is_eager=True,
            callback=callbacks.list_languages,
        ),
    ] = False,
    force: Annotated[
        bool, typer.Option("--force", help="Overwrite existing wrappers.")
    ] = False,
    wrapper_example: Annotated[
        int,
        typer.Option(
            "--example",
            help=(
                "The number of the example to get."
                " Check the documentation to see the available examples."
            ),
        ),
    ] = 0,
):
    """Fetches a wrapper template.

    Args:
        primitive: The primitive to get a wrapper of.
        directory: Where to copy the template to, current working directory by default.
        language: The programming language of the wrapper.
        show_languages: An option to display a list of primitives and the languages that
            have corresponding wrappers available. It's an eager option that uses the
            :func:`~crypto_condor.cli.callbacks.list_languages` callback, so the
            argument is not used in the function itself.
        force: Whether to overwrite existing templates in the given directory.
        wrapper_example: Number of the example to get.
    """
    prim = Primitive(primitive)
    rsc_dir = resources.files("crypto_condor") / f"resources/wrappers/{str(prim)}"
    languages = [str(w) for w in prim.get_languages()]
    while language not in languages:  # pragma: no cover (prompt)
        if language != "":
            console.print(f"There's no wrapper for {prim} in [yellow]{language}[/]")
        if len(languages) == 1:
            lang = languages[0]
            if Confirm.ask(
                f"Only the {str(lang)} wrapper is available, use it?", default=True
            ):
                language = lang
            else:
                raise typer.Exit(1)
        else:
            language = Prompt.ask(
                "Choose a language", choices=languages, default=languages[0]
            )

    if directory is None:
        dst_dir = Path.cwd()
    else:
        dst_dir = Path(directory)
        if dst_dir.is_file():
            raise FileExistsError(f"{str(dst_dir)} is a file")
        elif not dst_dir.is_dir():
            dst_dir.mkdir(0o700, parents=False, exist_ok=True)

    if wrapper_example > 0:
        src_dir = rsc_dir / f"{language}-examples" / str(wrapper_example)
    else:
        src_dir = rsc_dir / language

    overwritten = False
    for file in src_dir.iterdir():
        dst = dst_dir / file.name
        if not file.is_file():  # pragma: no cover (not needed)
            # Skip non-files, as building the package generates __pycache__.
            continue
        if not force and dst.exists():  # pragma: no cover (prompt)
            console.print(f"[yellow]{file.name}[/] already exists in {dst_dir}")
            typer.confirm("Do you want to overwrite it?", abort=True)
            overwritten = True
        shutil.copyfile(str(file), dst)
        console.print(f"Copied {file.name}")

    # Convoluted way of getting the name of the CLI command. The advantage is that this
    # will work after a proper name for the package is set.
    (cli_script,) = metadata.entry_points(value=f"{__name__}:app")
    cli_name = cli_script.name

    console.print()
    console.print(
        f"Copied wrapper for {primitive} in {language} to {dst_dir}."
        f" Fill it and then run it with [blue]{cli_name} test wrapper {primitive}[/].",
    )
    if overwritten:  # pragma: no cover (depends on prompt)
        console.print("You can overwrite files with the --force option")


_testu01_help = """Test the output of a PRNG using TestU01.

TestU01 is ``a software library, implemented in the ANSI C language, and offering a collection of utilities for the empirical statistical testing of uniform random number generators''.

crypto-condor bundles this library with Quarkslab's modifications to run the NIST battery of tests.  This library is installed automagically during the first use of this command. Its location is OS-dependent, you can use the --where option to show where it is installed on your system.
"""  # noqa: E501


@app.command(name="testu01", help=_testu01_help, rich_help_panel="Test PRNG")
def testu01(
    file: Annotated[
        Path,
        typer.Argument(help="File to test.", file_okay=True, readable=True),
    ],
    bit_count: Annotated[
        int,
        typer.Option(
            "--bit-count",
            "-b",
            help=(
                "The number of bits to read, must be less or equal to the file's size."
                " By default reads the entire file."
            ),
            show_default=False,
        ),
    ] = 0,
    where: Annotated[
        bool,
        typer.Option(
            "--where",
            help="Show where TestU01 is installed on your system and exit.",
            callback=callbacks.print_testu01_install_dir,
            is_eager=True,
            show_default=False,
        ),
    ] = False,
    filename: Annotated[
        str,
        typer.Option(
            "--save-to",
            help=(
                "Name of the file to save the results,"
                " the .txt extension is added automatically."
            ),
            metavar="FILE",
        ),
    ] = "",
    no_save: Annotated[
        bool, typer.Option("--no-save", help="Do not prompt to save results.")
    ] = False,
):
    """Tests the output of a PRNG using TestU01.

    Args:
        file: The name of the file to use.
        bit_count: The number of bits to test. Must be less or equal to the actual size
            of the file.
        where: Calls :func:`crypto_condor.cli.callbacks.print_testu01_install_dir`.
        filename: Name of the file to save results.
        no_save: Do not save results or prompt the user.
    """
    from crypto_condor.primitives import TestU01

    results = TestU01.test_file(str(file), bit_count=bit_count)
    if results is None:  # pragma: no cover (requires error)
        logger.error("Could not test file")
        raise typer.Exit(1)
    if console.process_results(results, filename, no_save):
        raise typer.Exit(0)
    else:
        raise typer.Exit(1)


_main_help = r"""[bold]crypto-condor[/] is a tool for compliance testing of implementations of cryptographic primitives.

This CLI uses commands, similar to Git. To get information on any command, use its --help option.
"""  # noqa: E501


@app.callback(help=_main_help)
def main(
    verbose: Annotated[
        int,
        typer.Option(
            "-v",
            "--verbose",
            count=True,
            show_default=False,
            help=(
                "Can be used repeatedly to increase verbosity."
                " Must be used before other commands."
            ),
            metavar="",
        ),
    ] = 0,
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            help="Print the version.",
            is_eager=True,
            callback=callbacks.print_version,
        ),
    ] = False,
):
    """Main function.

    Args:
        verbose: The level of verbosity. Typer counts the number of occurrences of '-v'
            when using the CLI.
        version: Displays the version and exits. It's an eager option that uses the
            :func:`~crypto_condor.cli.callbacks.print_version` callback.
    """
    set_logging(verbose)
    if verbose >= 2:
        app.pretty_exceptions_show_locals = True
