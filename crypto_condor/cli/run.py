"""Module for the "test wrapper" command."""

import logging
from pathlib import Path
from subprocess import SubprocessError
from typing import Annotated, Optional

import strenum
import typer
from rich.prompt import Prompt

from crypto_condor.primitives import (
    ECDSA,
    MLDSA,
    MLKEM,
    RSAES,
    RSASSA,
    SHA,
    ChaCha20,
)
from crypto_condor.primitives.common import Console

# --------------------------- Module --------------------------------------------------

logger = logging.getLogger(__name__)
console = Console()

_run_help = """Run a wrapper.

To get a wrapper, use [cyan]crypto-condor-cli get-wrapper[/]. After filling it, use this command to run it.

Don't change the name of the files provided: the subcommands have a list of files to run or import depending on the primitive and languages select.
"""  # noqa: E501
app = typer.Typer(
    help=_run_help,
    no_args_is_help=True,
    context_settings={"max_content_width": console.width},
)


# --------------------------- Enums ---------------------------------------------------


class AesStrKeyLength(strenum.StrEnum):
    """Workaround for using IntEnum with Typer.

    Typer/Click don't handle ints as choices from an enum, so mimic the real enum with
    str values and convert back when calling the function.
    """

    ALL = "0"
    AES128 = "128"
    AES192 = "192"
    AES256 = "256"


# --------------------------- Common arguments ----------------------------------------

_language = typer.Argument(
    help="The language of the wrapper.", show_default=False, case_sensitive=False
)
_mode = typer.Argument(
    help="The mode of operation.", show_default=False, case_sensitive=False
)
_compliance = typer.Option(
    "--compliance/--no-compliance", help="Use compliance test vectors."
)
_resilience = typer.Option(
    "--resilience/--no-resilience", help="Use resilience test vectors."
)
_encrypt = typer.Option("--encrypt/--no-encrypt", help="Test the encryption function.")
_decrypt = typer.Option("--decrypt/--no-decrypt", help="Test the decryption function.")
_sign = typer.Option("--sign/--no-sign", help="Test the signing function.")
_verify = typer.Option("--verify/--no-verify", help="Test the verifying function.")
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

# --------------------------- Subcommands ---------------------------------------------

# TODO: expand.
_aes_help = """Run an AES wrapper."""


@app.command(name="AES", no_args_is_help=True, help=_aes_help)
@app.command(name="aes", no_args_is_help=True, help=_aes_help, hidden=True)
def aes(
    wrapper: Annotated[Path, typer.Argument(metavar="FILE")],
    compliance: Annotated[bool, _compliance] = True,
    resilience: Annotated[bool, _resilience] = False,
    filename: Annotated[str, _filename] = "",
    no_save: Annotated[bool, _no_save] = False,
    debug: Annotated[Optional[bool], _debug] = None,
):
    """Runs an AES wrapper.

    Args:
        wrapper: The wrapper to test.

    Keyword Args:
        compliance: Whether to use compliance test vectors.
        resilience: Whether to use resilience test vectors.
        filename: Name of the file to save results.
        no_save: Do not save results or prompt the user.
        debug: When saving the results to a file, whether to add the debug data.
    """
    from crypto_condor.primitives import AES

    if not compliance and not resilience:  # pragma: no cover (not needed)
        console.print(
            "--no-compliance and --no-resilience used, no test vectors to use!"
        )
        raise typer.Exit(1)

    if not wrapper.is_file():
        raise FileNotFoundError(f"AES wrapper not found: {str(wrapper)}")

    match wrapper.suffix:
        case ".py":
            rd = AES.run_python_wrapper(wrapper, compliance, resilience)
        case _:
            console.print(
                f"There is no AES runner defined for {wrapper.suffix} wrappers"
            )
            raise typer.Exit(1)
    if console.process_results(rd, filename, no_save, debug):
        raise typer.Exit(0)
    else:
        raise typer.Exit(1)


_ecdsa_help = """Run an ECDSA wrapper.

Test an implementation of ECDSA signature generation or verification. By default both functions are tested separately (`--sign` and `--verify`). You can also test both consecutively with `--sign-then-verify`.

Disabling all three options (`--sign`, `--verify`, and `--sign-then-verify`) means that no tests are run.

Disabling both types of test vectors (`--no-compliance` and `--no-resilience`) means that `--sign` and `--verify` can't be run. `--sign-then-verify` uses randomly generated values so it is not affected.

Example:

    crypto-condor-cli test wrapper ECDSA Python secp256r1 SHA-256 --key-encoding DER --pubkey-encoding DER
"""  # noqa: E501


@app.command(name="ECDSA", no_args_is_help=True, help=_ecdsa_help)
@app.command(name="ecdsa", no_args_is_help=True, help=_ecdsa_help, hidden=True)
def ecdsa(
    language: Annotated[ECDSA.Wrapper, _language],
    curve: Annotated[
        ECDSA.Curve,
        typer.Argument(
            help="The elliptic curve to use.", show_default=False, case_sensitive=False
        ),
    ],
    hash_function: Annotated[
        ECDSA.Hash,
        typer.Argument(
            help="The hash function to use.", show_default=False, case_sensitive=False
        ),
    ],
    key_encoding: Annotated[
        Optional[ECDSA.KeyEncoding],
        typer.Option(
            "--key-encoding",
            help=(
                "The encoding used for private keys."
                " Required when testing the signing function."
            ),
            case_sensitive=False,
        ),
    ] = None,
    pubkey_encoding: Annotated[
        Optional[ECDSA.PubKeyEncoding],
        typer.Option(
            "--pubkey-encoding",
            help=(
                "The encoding used for public keys."
                " Required when testing the verifying function."
            ),
            case_sensitive=False,
        ),
    ] = None,
    pre_hashed: Annotated[
        bool,
        typer.Option(
            "--pre-hashed",
            help="Whether the message should be hashed before passing to the function.",
        ),
    ] = False,
    compliance: Annotated[bool, _compliance] = True,
    resilience: Annotated[bool, _resilience] = False,
    test_sign: Annotated[bool, _sign] = True,
    test_verify: Annotated[bool, _verify] = True,
    test_sign_then_verify: Annotated[
        bool,
        typer.Option(
            "--sign-then-verify/--no-sign-then-verify",
            help="Test both functions by signing then verifying the signature.",
        ),
    ] = False,
    filename: Annotated[str, _filename] = "",
    no_save: Annotated[bool, _no_save] = False,
    debug: Annotated[Optional[bool], _debug] = None,
):
    """Runs an ECDSA wrapper.

    Args:
        language: The language of the wrapper.
        curve: The elliptic curve to use.
        hash_function: The hash function to use.
        key_encoding: The encoding used for private keys.
        pubkey_encoding: The encoding used for public keys.
        pre_hashed: Whether the messages given to the implementation must be hashed
            first.
        compliance: Whether to use compliance test vectors.
        resilience: Whether to use resilience test vectors.
        test_sign: Whether to test the signing function.
        test_verify: Whether to test the verifying function.
        test_sign_then_verify: Whether to test both functions by signing then verifying.
        filename: Name of the file to save results.
        no_save: Do not save results or prompt the user.
        debug: When saving the results to a file, whether to add the debug data.

    Notes:
        - :attr:`compliance` and :attr:`resilience` should not be False at the same time
          unless :attr:`test_sign_then_verify` is used.
        - :attr:`test_sign`, :attr:`test_verify`, and :attr:`test_sign_then_verify`
          should not be False at the same time.
    """
    if (
        not test_verify and not test_sign and not test_sign_then_verify
    ):  # pragma: no cover(not needed)
        console.print(
            "--no-verify, --no-sign, and --no-sign-then-verify used: no tests selected"
        )
        raise typer.Exit(1)
    if not compliance and not resilience:  # pragma: no cover (not needed)
        if test_sign:
            console.print(
                "--no-compliance and --no-resilience used with --sign:",
                "no test vectors to use",
            )
            raise typer.Exit(1)
        if test_verify:
            console.print(
                "--no-compliance and --no-resilience used with --verify:",
                "no test vectors to use",
            )
            raise typer.Exit(1)

    while (
        test_sign or test_sign_then_verify
    ) and not key_encoding:  # pragma: no cover (prompt)
        key_encoding = ECDSA.KeyEncoding(
            Prompt.ask(
                "Select a private key encoding",
                choices=[str(e) for e in ECDSA.KeyEncoding],
            )
        )
    while (
        test_verify or test_sign_then_verify
    ) and not pubkey_encoding:  # pragma: no cover (prompt)
        pubkey_encoding = ECDSA.PubKeyEncoding(
            Prompt.ask(
                "Select a public key encoding",
                choices=[e for e in ECDSA.PubKeyEncoding],
            )
        )

    try:
        results = ECDSA.run_wrapper(
            language,
            curve,
            hash_function,
            pre_hashed,
            test_sign,
            key_encoding,
            test_verify,
            pubkey_encoding,
            test_sign_then_verify,
            compliance,
            resilience,
        )
    except FileNotFoundError as error:
        logger.error(error)
        raise typer.Exit(1) from error
    if console.process_results(results, filename, no_save, debug):
        raise typer.Exit(0)
    else:
        raise typer.Exit(1)


# TODO: expand.
_sha_help = "Run a SHA wrapper."


@app.command(name="SHA", no_args_is_help=True, help=_sha_help)
@app.command(name="sha", no_args_is_help=True, help=_sha_help, hidden=True)
def sha(
    wrapper: Annotated[str, typer.Argument(metavar="FILE")],
    compliance: Annotated[bool, _compliance] = True,
    resilience: Annotated[bool, _resilience] = False,
    filename: Annotated[str, _filename] = "",
    no_save: Annotated[bool, _no_save] = False,
    debug: Annotated[Optional[bool], _debug] = None,
):
    """Runs a SHA wrapper.

    Args:
        wrapper:
            The wrapper to test.

    Keyword Args:
        compliance:
            Whether to use compliance test vectors.
        resilience:
            Whether to use resilience test vectors.
        filename:
            Name of the file to save results.
        no_save:
            Do not save results or prompt the user.
        debug:
            When saving the results to a file, whether to add the debug data.
    """
    try:
        results = SHA.test_wrapper(Path(wrapper), compliance, resilience)
    except ValueError as error:
        logger.error(error)
        raise typer.Exit(1) from error
    if console.process_results(results, filename, no_save, debug):
        raise typer.Exit(0)
    else:
        raise typer.Exit(1)


# TODO: expand.
_shake_help = "Run a SHAKE wrapper."


@app.command(name="SHAKE", no_args_is_help=True, help=_shake_help)
@app.command(name="shake", no_args_is_help=True, help=_shake_help, hidden=True)
def shake(
    wrapper: Annotated[Path, typer.Argument(metavar="FILE")],
    filename: Annotated[str, _filename] = "",
    no_save: Annotated[bool, _no_save] = False,
    debug: Annotated[Optional[bool], _debug] = None,
    compliance: Annotated[bool, _compliance] = True,
    resilience: Annotated[bool, _resilience] = False,
):
    """Runs a SHAKE wrapper.

    Args:
        wrapper: The wrapper to test.

    Keyword Args:
        filename: Name of the file to save results.
        no_save: Do not save results or prompt the user.
        debug: When saving the results to a file, whether to add the debug data.
        compliance: Whether to use compliance test vectors.
        resilience: Whether to use resilience test vectors.
    """
    if not wrapper.is_file():
        raise FileNotFoundError(f"Could not find wrapper {str(wrapper)}")

    from crypto_condor.primitives import SHAKE

    match wrapper.suffix:
        case ".py":
            rd = SHAKE.run_python_wrapper(wrapper, compliance, resilience)
        case _:
            console.print(f"There are no runners for {wrapper.stem} wrappers")
            raise typer.Exit(1)
    if console.process_results(rd, filename, no_save, debug):
        raise typer.Exit(0)
    else:
        raise typer.Exit(1)


# TODO: expand.
_rsassa_help = """Run an RSASSA wrapper.

Tests implementations of RSA signature schemes RSASSA-PKCS1-v1_5 and RSASSA-PSS.
"""


@app.command(name="RSASSA", no_args_is_help=True, help=_rsassa_help)
@app.command(name="rsassa", no_args_is_help=True, help=_rsassa_help, hidden=True)
def rsassa(
    language: Annotated[RSASSA.Wrapper, _language],
    scheme: Annotated[
        RSASSA.Scheme,
        typer.Argument(
            help=("The signature scheme to test."),
            show_default=False,
            case_sensitive=False,
        ),
    ],
    sha: Annotated[
        RSASSA.Hash,
        typer.Argument(
            help="The SHA algorithm to use for signatures.",
            show_default=False,
            case_sensitive=False,
        ),
    ],
    mgf_sha: Annotated[
        Optional[RSASSA.Hash],
        typer.Option(
            "--mgf-sha",
            help="(RSASSA-PSS only) The SHA algorithm to use with MGF1.",
            show_default=False,
            case_sensitive=False,
        ),
    ] = None,
    sign: Annotated[bool, _sign] = True,
    verify: Annotated[bool, _verify] = True,
    filename: Annotated[str, _filename] = "",
    no_save: Annotated[bool, _no_save] = False,
    debug: Annotated[Optional[bool], _debug] = None,
):
    """Runs an RSA wrapper.

    Args:
        language: The language of the wrapper to run.
        scheme: The RSA scheme to test.
        sha: The SHA to use.
        mgf_sha: (RSASSA-PSS only) The SHA to use with MGF1.
        sign: Whether to test the signing function.
        verify: Whether to test the verifying function.
        filename: Name of the file to save results.
        no_save: Do not save results or prompt the user.
        debug: When saving the results to a file, whether to add the debug data.
    """
    try:
        results = RSASSA.run_wrapper(language, scheme, sha, mgf_sha, sign, verify)
    except Exception as error:
        logger.error(error)
        raise typer.Exit(1) from error
    if console.process_results(results, filename, no_save, debug):
        raise typer.Exit(0)
    else:
        raise typer.Exit(1)


# TODO: expand.
_rsaes_help = """Run an RSAES wrapper.

Tests implementations of RSA encryption schemes RSAES-PKCS1-v1_5 and RSAES-OAEP.
"""


@app.command(name="RSAES", no_args_is_help=True, help=_rsaes_help)
@app.command(name="rsaes", no_args_is_help=True, help=_rsaes_help, hidden=True)
def rsaes(
    language: Annotated[RSAES.Wrapper, _language],
    scheme: Annotated[
        RSAES.Scheme,
        typer.Argument(
            help="The encryption scheme to test.",
            show_default=False,
            case_sensitive=False,
        ),
    ],
    sha: Annotated[
        Optional[RSAES.Hash],
        typer.Option(
            help="(RSAES-OAEP only) The SHA algorithm to use.",
            show_default=False,
            case_sensitive=False,
        ),
    ] = None,
    mgf_sha: Annotated[
        Optional[RSAES.Hash],
        typer.Option(
            "--mgf-sha",
            help="(RSAES-OAEP only) The SHA algorithm to use with MGF1.",
            show_default=False,
            case_sensitive=False,
        ),
    ] = None,
    filename: Annotated[str, _filename] = "",
    no_save: Annotated[bool, _no_save] = False,
    debug: Annotated[Optional[bool], _debug] = None,
):
    """Runs a RSAES wrapper.

    Args:
        language: The language of the wrapper to run.
        scheme: The RSA scheme to test.
        sha: The SHA to use in RSAES-OAEP.
        mgf_sha: The SHA to use with MGF1 in RSAES-OAEP.
        filename: Name of the file to save results.
        no_save: Do not save results or prompt the user.
        debug: When saving the results to a file, whether to add the debug data.
    """
    try:
        results = RSAES.run_rsaes_wrapper(language, scheme, sha, mgf_sha)
    except Exception as error:
        logger.error(error)
        raise typer.Exit(1) from error
    if console.process_results(results, filename, no_save, debug):
        raise typer.Exit(0)
    else:
        raise typer.Exit(1)


# TODO: expand.
_chacha20_help = """Run an ChaCha20 wrapper."""


@app.command(name="ChaCha20", no_args_is_help=True, help=_chacha20_help)
@app.command(name="chacha20", no_args_is_help=True, help=_chacha20_help, hidden=True)
def chacha20(
    language: Annotated[ChaCha20.Wrapper, _language],
    mode: Annotated[ChaCha20.Mode, _mode],
    resilience: Annotated[bool, _resilience] = True,
    encrypt: Annotated[bool, _encrypt] = True,
    decrypt: Annotated[bool, _decrypt] = True,
    filename: Annotated[str, _filename] = "",
    no_save: Annotated[bool, _no_save] = False,
    debug: Annotated[Optional[bool], _debug] = None,
):
    """Runs an ChaCha20 wrapper.

    Args:
        language: The language of the wrapper.
        mode: The mode of operation.
        resilience: Whether to use resilience test vectors.
        encrypt: Whether to test encryption.
        decrypt: Whether to test decryption.
        filename: Name of the file to save results.
        no_save: Do not save results or prompt the user.
        debug: When saving the results to a file, whether to add the debug data.

    Notes:
        - encrypt and decrypt should not be False at the same time.
        - If resilience if False, no test can be done.
    """
    if not encrypt and not decrypt:  # pragma: no cover (not needed)
        console.print("--no-encrypt and --no-decrypt used, no operation to test.")
        raise typer.Exit(1)
    if not resilience:  # pragma: no cover (not needed)
        console.print("--no-resilience used, no test vectors to use.")
        raise typer.Exit(1)

    try:
        results = ChaCha20.run_wrapper(
            language, mode, resilience=resilience, encrypt=encrypt, decrypt=decrypt
        )
    except (SubprocessError, ValueError, FileNotFoundError) as error:
        console.print(error)
        raise typer.Exit(1) from error
    if console.process_results(results, filename, no_save, debug):
        raise typer.Exit(0)
    else:
        raise typer.Exit(1)


# TODO: expand.
_hmac_help = """Run an HMAC wrapper."""


@app.command(name="HMAC", no_args_is_help=True, help=_hmac_help)
@app.command(name="hmac", no_args_is_help=True, help=_hmac_help, hidden=True)
def hmac(
    wrapper: Annotated[str, typer.Argument(metavar="FILE")],
    compliance: Annotated[bool, _compliance] = True,
    resilience: Annotated[bool, _resilience] = False,
    filename: Annotated[str, _filename] = "",
    no_save: Annotated[bool, _no_save] = False,
    debug: Annotated[Optional[bool], _debug] = None,
):
    """Runs an HMAC wrapper."""
    from crypto_condor.primitives import HMAC

    try:
        rd = HMAC.test_wrapper(Path(wrapper), compliance, resilience)
    except (FileNotFoundError, ValueError) as error:
        console.print(str(error))
        raise typer.Exit(1) from error
    if console.process_results(rd, filename, no_save, debug):
        raise typer.Exit(0)
    else:
        raise typer.Exit(1)


_ecdh_help = "Run an ECDH wrapper."


@app.command(name="ECDH", no_args_is_help=True, help=_ecdh_help)
@app.command(name="ecdh", no_args_is_help=True, help=_ecdh_help, hidden=True)
def ecdh(
    wrapper: Annotated[
        Path, typer.Argument(metavar="FILE", help="The wrapper to test.")
    ],
    compliance: Annotated[bool, _compliance] = True,
    resilience: Annotated[bool, _resilience] = False,
    filename: Annotated[str, _filename] = "",
    no_save: Annotated[bool, _no_save] = False,
    debug: Annotated[Optional[bool], _debug] = None,
):
    """Runs an ECDH wrapper.

    Args:
        lang: The language of the wrapper.
        curve: The elliptic curve to use.
        wrapper: The name of the wrapper, ECDH_wrapper.py by default.
        compliance: Whether to use compliance test vectors.
        resilience: Whether to use resilience test vectors.
        filename: Name of the file to save results.
        no_save: Do not save results or prompt the user.
        debug: When saving the results to a file, whether to add the debug data.
    """
    from crypto_condor.primitives import ECDH

    try:
        results = ECDH.test_wrapper(wrapper, compliance, resilience)
    except (FileNotFoundError, ModuleNotFoundError) as error:
        raise typer.Exit(1) from error
    if console.process_results(results, filename, no_save, debug):
        raise typer.Exit(0)
    else:
        raise typer.Exit(1)


# TODO: expand.
_mlkem_help = "Run a ML-KEM wrapper"


@app.command(name="MLKEM", no_args_is_help=True, help=_mlkem_help)
@app.command(name="mlkem", no_args_is_help=True, help=_mlkem_help, hidden=True)
def mlkem(
    wrapper: Annotated[Path, typer.Argument()],
    compliance: Annotated[bool, _compliance] = True,
    resilience: Annotated[bool, _resilience] = False,
    filename: Annotated[str, _filename] = "",
    no_save: Annotated[bool, _no_save] = False,
    debug: Annotated[Optional[bool], _debug] = None,
):
    """Runs a ML-KEM wrapper.

    Args:
        wrapper: The wrapper to test.
        compliance: Whether to use compliance test vectors.
        resilience: Whether to use resilience test vectors.
        filename: Name of the file to save results.
        no_save: Do not save results or prompt the user.
        debug: When saving the results to a file, whether to add the debug data.
    """
    if not wrapper.is_file():
        raise FileNotFoundError(f"ML-KEM wrapper not found: {str(wrapper)}")

    match wrapper.suffix:
        case ".py":
            results = MLKEM.run_python_wrapper(wrapper, compliance, resilience)
        case _:
            console.print(
                "There is no ML-KEM runner defined for %s wrappers" % wrapper.suffix
            )
            raise typer.Exit(1)
    if console.process_results(results, filename, no_save, debug):
        raise typer.Exit(0)
    else:
        raise typer.Exit(1)


# TODO: expand.
_mldsa_help = "Run a ML-DSA wrapper."


@app.command(name="MLDSA", no_args_is_help=True, help=_mldsa_help)
@app.command(name="mldsa", no_args_is_help=True, help=_mldsa_help, hidden=True)
def mldsa(
    wrapper: Annotated[Path, typer.Argument()],
    compliance: Annotated[bool, _compliance] = True,
    resilience: Annotated[bool, _resilience] = False,
    filename: Annotated[str, _filename] = "",
    no_save: Annotated[bool, _no_save] = False,
    debug: Annotated[Optional[bool], _debug] = None,
):
    """Runs a ML-DSA wrapper.

    Args:
        wrapper: The wrapper to test.
        compliance: Whether to use compliance test vectors.
        resilience: Whether to use resilience test vectors.
        filename: Name of the file to save results.
        no_save: Do not save results or prompt the user.
        debug: When saving the results to a file, whether to add the debug data.
    """
    if not wrapper.is_file():
        raise FileNotFoundError(f"ML-DSA wrapper not found: {str(wrapper)}")

    match wrapper.suffix:
        case ".py":
            results = MLDSA.run_python_wrapper(wrapper, compliance, resilience)
        case _:
            console.print(
                "There is no ML-DSA runner defined for %s wrappers" % wrapper.suffix
            )
            raise typer.Exit(1)
    if console.process_results(results, filename, no_save, debug):
        raise typer.Exit(0)
    else:
        raise typer.Exit(1)
