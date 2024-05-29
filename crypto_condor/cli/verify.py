"""Module for the verify subcommand."""

import logging
from pathlib import Path
from typing import Annotated

import typer

from crypto_condor.primitives import AES, ECDSA, SHA, ChaCha20
from crypto_condor.primitives.common import Console

# --------------------------- Module --------------------------------------------------

logger = logging.getLogger(__name__)
console = Console()

_verify_help = """Verify the output of an implementation.

Test an implementation from a file containing a set of inputs and their
corresponding outputs.

To test a primitive, use the corresponding subcommand. Use --help to get
information on the format expected and specific options required for each
primitive.

It works by using the provided inputs as test vectors, which are run with an
internal implementation of the primitive, and then the outputs are compared.
"""

app = typer.Typer(no_args_is_help=True, help=_verify_help)


# --------------------------- Common arguments ----------------------------------------

_input_file = typer.Argument(
    help="Input file containing input/output data.",
    exists=True,
    file_okay=True,
    readable=True,
    show_default=False,
)
_filename = typer.Option(
    "--save-to",
    help=(
        "Name of the file to save the results,"
        " the .txt extension is added automatically."
    ),
    metavar="FILE",
)
_no_save = typer.Option("--no-save", help="Do not prompt to save results.")

# --------------------------- Commands ------------------------------------------------

_aes_help = r"""Verify an AES implementation.

The format of the file is the following:

- One set of arguments per line.
- Lines are separated by newlines ('\\n').
- Lines that start with '#' are counted as comments and ignored.
- Arguments are written in hexadecimal and separated by slashes.
- The order of the arguments in important and varies between modes of operation:
    - ECB: [blue]key/input/output[/]
    - CBC, CTR, and CFB*: [blue]key/input/output/iv[/]
    - CCM and GCM: [blue]key/input/output/iv/\[aad]/\[mac][/]
- Where:
    - [blue]key[/] is the key used.
    - [blue]input[/] is the plaintext when encrypting, the ciphertext when decrypting.
    - [blue]output[/] is the ciphertext when encrypting, the plaintext when decrypting.
    - [blue]iv[/] is the IV or nonce used for that operation.
    - [blue]aad[/] is the associated data. It is optional and can be empty, but the corresponding slashes must be present.
    - [blue]mac[/] is the MAC tag generated when encrypting. When testing encryption, it is compared to the MAC generated internally. When decrypting, it is used for authenticating the ciphertext and associated data.
"""  # noqa: E501


@app.command(
    name="AES",
    help=_aes_help,
    no_args_is_help=True,
    rich_help_panel="Subcommands",
    context_settings={"max_content_width": console.width},
)
@app.command(
    name="aes",
    help=_aes_help,
    no_args_is_help=True,
    rich_help_panel="Subcommands",
    context_settings={"max_content_width": console.width},
    hidden=True,
)
def aes(
    input_file: Annotated[Path, _input_file],
    mode: Annotated[
        AES.Mode,
        typer.Argument(help="The mode of operation.", show_default=False),
    ],
    operation: Annotated[
        AES.Operation,
        typer.Argument(
            help="The operation being tested, either encrypt or decrypt",
            show_default=False,
        ),
    ],
    filename: Annotated[str, _filename] = "",
    no_save: Annotated[bool, _no_save] = False,
):
    """Tests the output of an AES implementation.

    Args:
        input_file: The input file to read and parse.
        mode: The mode of operation.
        operation: The operation being tested (encrypt/decrypt).
        filename: Name of the file to save results.
        no_save: Do not save results or prompt the user.
    """
    try:
        results = AES.verify_file(str(input_file), mode, operation)
    except ValueError as error:
        logger.error(error)
        raise typer.Exit(1) from error
    if console.process_results(results, filename, no_save):
        raise typer.Exit(0)
    else:
        raise typer.Exit(1)


_ecdsa_help = """Verify ECDSA signatures.

The format is a work in progress, so it is subject to change.

- One line per signature.
- All arguments are given in hexadecimal.
- Arguments are separated by slashes.
- The order is important. The arguments are interpreted as: key, message, and signature.
"""


@app.command(
    name="ECDSA",
    help=_ecdsa_help,
    no_args_is_help=True,
    rich_help_panel="Subcommands",
    context_settings={"max_content_width": console.width},
)
@app.command(
    name="ecdsa",
    help=_ecdsa_help,
    no_args_is_help=True,
    rich_help_panel="Subcommands",
    context_settings={"max_content_width": console.width},
    hidden=True,
)
def ecdsa(
    input_file: Annotated[Path, _input_file],
    pubkey_encoding: Annotated[
        ECDSA.PubKeyEncoding,
        typer.Argument(
            help="The encoding used for the public keys.",
            show_default=False,
        ),
    ],
    hash_function: Annotated[
        ECDSA.Hash,
        typer.Argument(
            help="The hash function used to generate the signatures.",
            show_default=False,
        ),
    ],
    filename: Annotated[str, _filename] = "",
    no_save: Annotated[bool, _no_save] = False,
):
    """Tests ECDSA signatures.

    Args:
        input_file: The input file to read and parse.
        pubkey_encoding: The encoding used for the public keys.
        hash_function: The hash function used to generate the signatures.
        filename: Name of the file to save results.
        no_save: Do not save results or prompt the user.
    """
    try:
        results = ECDSA.verify_file(str(input_file), pubkey_encoding, hash_function)
    except (ValueError, IOError) as error:
        console.print(str(error))
        raise typer.Exit(1) from error
    if console.process_results(results, filename, no_save):
        raise typer.Exit(0)
    else:
        raise typer.Exit(1)


_sha_help = """Tests a file of SHA hashes.

The format of the file is:

- One input per line.
- The message and the resulting hash in hexadecimal.
- Separated by a slash.
"""


@app.command(
    name="SHA",
    help=_sha_help,
    no_args_is_help=True,
    rich_help_panel="Subcommands",
    context_settings={"max_content_width": console.width},
)
@app.command(
    name="sha",
    help=_sha_help,
    no_args_is_help=True,
    rich_help_panel="Subcommands",
    context_settings={"max_content_width": console.width},
    hidden=True,
)
def sha(
    input_file: Annotated[Path, _input_file],
    algorithm: Annotated[
        SHA.Algorithm,
        typer.Argument(help="The hash algorithm to test.", show_default=False),
    ],
    filename: Annotated[str, _filename] = "",
    no_save: Annotated[bool, _no_save] = False,
):
    """Tests SHA hashes.

    Args:
        input_file: The input file.
        algorithm: The hash algorithm used.
        filename: Name of the file to save results.
        no_save: Do not save results or prompt the user.
    """
    try:
        results = SHA.verify_file(str(input_file), algorithm)
    except ValueError as error:
        console.print(error)
        raise typer.Exit(1) from error
    if console.process_results(results, filename, no_save):
        raise typer.Exit(0)
    else:
        raise typer.Exit(1)


_chacha20_help = """Verify a ChaCha20 implementation.

The format is a work in progress, so it is subject to change.

- One line per encryption.
- All arguments are given in hexadecimal.
- Arguments are separated by slashes.
- The order is important and depends on the mode being tested:
    - CHACHA20: key/input/output/nonce/[init_counter]
    - CHACHA20-POLY1305: key/input/output/nonce/mac/[aad]

Arguments in brackets are optional, if not in use simply end the line after the
last required argument.

Modes of operation:
    - CHACHA20
    - CHACHA20-POLY1305
"""


@app.command(
    name="ChaCha20",
    help=_chacha20_help,
    no_args_is_help=True,
    rich_help_panel="Subcommands",
    context_settings={"max_content_width": console.width},
)
@app.command(
    name="chacha20",
    help=_chacha20_help,
    no_args_is_help=True,
    rich_help_panel="Subcommands",
    context_settings={"max_content_width": console.width},
    hidden=True,
)
def chacha20(
    input_file: Annotated[Path, _input_file],
    mode: Annotated[
        ChaCha20.Mode,
        typer.Argument(help="The mode of operation.", show_default=False),
    ],
    operation: Annotated[
        ChaCha20.Operation,
        typer.Argument(
            help="The operation being tested, either encrypt or decrypt",
            show_default=False,
        ),
    ],
    filename: Annotated[str, _filename] = "",
    no_save: Annotated[bool, _no_save] = False,
):
    """Tests the output of an ChaCha20 implementation.

    Args:
        input_file: The input file to read and parse.
        mode: The mode of operation.
        operation: The operation being tested (encrypt/decrypt).
        filename: Name of the file to save results.
        no_save: Do not save results or prompt the user.
    """
    try:
        results = ChaCha20.verify_file(str(input_file), ChaCha20.Mode(mode), operation)
    except ValueError as error:
        console.print(error)
        raise typer.Exit(1) from error
    if console.process_results(results, filename, no_save):
        raise typer.Exit(0)
    else:
        raise typer.Exit(1)
