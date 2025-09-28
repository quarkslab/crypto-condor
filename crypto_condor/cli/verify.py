"""Module for the verify subcommand."""

import logging
from pathlib import Path
from typing import Annotated, Optional

import strenum
import typer

from crypto_condor.primitives import AES, ECDSA, SHA, SHAKE, ChaCha20
from crypto_condor.primitives.common import Console
from crypto_condor.vectors import hmac

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
_debug = typer.Option(
    "--debug/--no-debug", help="When saving results, whether to include debug data"
)

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

    Keyword Args:
        filename: Name of the file to save results.
        no_save: Do not save results or prompt the user.
    """
    if operation == "encrypt":
        try:
            results = AES.test_output_encrypt(str(input_file), mode)
        except ValueError as error:
            logger.error(str(error))
            raise typer.Exit(1) from error
    else:
        try:
            results = AES.test_output_decrypt(str(input_file), mode)
        except ValueError as error:
            logger.error(str(error))
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

- One set of arguments per line.
- Lines are separated by newlines (``\n``).
- Lines that start with '#' are counted as comments and ignored.
- Arguments are written in hexadecimal and separated by slashes.
- The order of arguments is:

    message/hash
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
        input_file:
            The input file.
        algorithm:
            The hash algorithm used.
        filename:
            Name of the file to save results.
        no_save:
            Do not save results or prompt the user.
    """
    try:
        results = SHA.test_output_digest(str(input_file), algorithm)
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
    match (mode, operation):
        case (ChaCha20.Mode.CHACHA20, ChaCha20.Operation.ENCRYPT):
            results = ChaCha20.test_output_encrypt(input_file)
        case (ChaCha20.Mode.CHACHA20, ChaCha20.Operation.DECRYPT):
            results = ChaCha20.test_output_decrypt(input_file)
        case (ChaCha20.Mode.CHACHA20_POLY1305, ChaCha20.Operation.ENCRYPT):
            results = ChaCha20.test_output_encrypt_poly(input_file)
        case (ChaCha20.Mode.CHACHA20_POLY1305, ChaCha20.Operation.DECRYPT):
            results = ChaCha20.test_output_decrypt_poly(input_file)

    if console.process_results(results, filename, no_save):
        raise typer.Exit(0)
    else:
        raise typer.Exit(1)


_shake_help = """Test the output of a SHAKE implementation.

The format of the output file is as follows:

- One line per operation, separated by newlines ``\n``.
- Lines starting with ``#`` are considered comments and ignored.
- Values are written in hexadecimal.
- Values are separated by forward slashes ``/``.
- The order of the values is:

    ``msg/out``

Where:
    - ``msg`` is the input message to hash.
    - ``out`` is the result.
"""


@app.command(
    name="SHAKE",
    help=_shake_help,
    no_args_is_help=True,
    rich_help_panel="Subcommands",
    context_settings={"max_content_width": console.width},
)
@app.command(
    name="shake",
    help=_shake_help,
    no_args_is_help=True,
    rich_help_panel="Subcommands",
    context_settings={"max_content_width": console.width},
    hidden=True,
)
def shake(
    input_file: Annotated[Path, typer.Argument(metavar="FILE")],
    algorithm: Annotated[
        SHAKE.Algorithm,
        typer.Argument(help="The SHAKE algorithm used to generate the file."),
    ],
    filename: Annotated[str, _filename] = "",
    no_save: Annotated[bool, _no_save] = False,
    debug: Annotated[Optional[bool], _debug] = None,
):
    """Tests the output of a SHAKE implementation.

    Args:
        input_file: The file to test.
        algorithm: The SHAKE variant used to generate the outputs.

    Keyword Args:
        filename: The name of the file to save the results.
        no_save: If True, results are not saved and the user is not prompted.
        debug: If the results are saved, include debug data.
    """
    rd = SHAKE.test_output_digest(input_file, algorithm)
    if console.process_results(rd, filename, no_save, debug):
        raise typer.Exit(0)
    else:
        raise typer.Exit(1)


_hmac_help = """Test the output of an HMAC implementation.

The format of the output file is as follows:

- One line per operation, separated by newlines ``\n``.
- Lines starting with ``#`` are considered comments and ignored.
- Values are written in hexadecimal.
- Values are separated by forward slashes ``/``.
- The order of the values is:

    ``key/message/mac``
"""


@app.command(
    name="HMAC",
    help=_hmac_help,
    no_args_is_help=True,
    rich_help_panel="Subcommands",
    context_settings={"max_content_width": console.width},
)
@app.command(
    name="hmac",
    help=_hmac_help,
    no_args_is_help=True,
    rich_help_panel="Subcommands",
    context_settings={"max_content_width": console.width},
    hidden=True,
)
def test_hmac(
    input_file: Annotated[str, typer.Argument(metavar="FILE")],
    hash_function: Annotated[
        hmac.Hash,
        typer.Argument(help="The hash function used to generate the HMAC tags."),
    ],
    filename: Annotated[str, _filename] = "",
    no_save: Annotated[bool, _no_save] = False,
    debug: Annotated[Optional[bool], _debug] = None,
):
    """Tests the output of a SHAKE implementation.

    Args:
        input_file:
            The file to test.
        hash_function:
            The hash function used to generate the HMAC tags.

    Keyword Args:
        filename:
            The name of the file to save the results.
        no_save:
            If True, results are not saved and the user is not prompted.
        debug:
            If the results are saved, include debug data.
    """
    from crypto_condor.primitives import HMAC

    path = Path(input_file)
    if not path.is_file():
        console.print(f"Cannot find file {input_file}")
        raise typer.Exit(1)

    rd = HMAC.test_output_digest(path, hash_function)
    if console.process_results(rd, filename, no_save, debug):
        raise typer.Exit(0)
    else:
        raise typer.Exit(1)


_ecdh_help = r"""Test the output of an ECDH implementation.

The format of the output file is as follows:

- One line per operation, separated by newlines ``\n``.
- Lines starting with ``#`` are considered comments and ignored.
- Values are written in hexadecimal.
- Values are separated by forward slashes ``/``.
- The order of the values is:

    ``d/pk/secret``

Where:

- ``d`` is the secret scalar.
- ``pk`` is the peer's DER-encoded public key.
- ``secret`` is the resulting shared secret.
"""


class EcdhCurve(strenum.StrEnum):
    """Elliptic curves supported by cryptography."""

    P192 = "P-192"
    P224 = "P-224"
    P256 = "P-256"
    P384 = "P-384"
    P521 = "P-521"
    K163 = "K-163"
    K233 = "K-233"
    K283 = "K-283"
    K409 = "K-409"
    K571 = "K-571"
    B163 = "B-163"
    B233 = "B-233"
    B283 = "B-283"
    B409 = "B-409"
    B571 = "B-571"
    BRAINPOOLP256R1 = "brainpoolP256r1"
    BRAINPOOLP384R1 = "brainpoolP384r1"
    BRAINPOOLP512R1 = "brainpoolP512r1"
    SECP256K1 = "secp256k1"


@app.command(
    name="ECDH",
    help=_ecdh_help,
    no_args_is_help=True,
    rich_help_panel="Subcommands",
    context_settings={"max_content_width": console.width},
)
@app.command(
    name="ecdh",
    help=_ecdh_help,
    no_args_is_help=True,
    rich_help_panel="Subcommands",
    context_settings={"max_content_width": console.width},
    hidden=True,
)
def test_ecdh(
    input_file: Annotated[str, typer.Argument(metavar="FILE", show_default=False)],
    curve: Annotated[
        EcdhCurve,
        typer.Argument(
            help=(
                "The elliptic curve used for the exchange."
                f" One of: {', '.join([str(c) for c in EcdhCurve])}"
            ),
            metavar="STRING",
            show_default=False,
        ),
    ],
    filename: Annotated[str, _filename] = "",
    no_save: Annotated[bool, _no_save] = False,
    debug: Annotated[Optional[bool], _debug] = None,
):
    """Tests the output of a SHAKE implementation.

    Args:
        input_file:
            The file to test.
        curve:
            The elliptic curve used for the exchange.

    Keyword Args:
        filename:
            The name of the file to save the results.
        no_save:
            If True, results are not saved and the user is not prompted.
        debug:
            If the results are saved, include debug data.
    """
    from crypto_condor.primitives import ECDH

    path = Path(input_file)
    if not path.is_file():
        console.print(f"Cannot find file {input_file}")
        raise typer.Exit(1)

    cc_curve = ECDH.Curve.from_name(str(curve))

    rd = ECDH.test_output_exchange(path, cc_curve)
    if console.process_results(rd, filename, no_save, debug):
        raise typer.Exit(0)
    else:
        raise typer.Exit(1)
