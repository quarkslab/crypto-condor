"""Module for the "test wrapper" command."""

import logging
from pathlib import Path
from subprocess import SubprocessError
from typing import Annotated, Optional

import strenum
import typer
from rich.prompt import Prompt

from crypto_condor.primitives import (
    AES,
    ECDH,
    ECDSA,
    HMAC,
    RSAES,
    RSASSA,
    SHA,
    SHAKE,
    ChaCha20,
    Dilithium,
    Kyber,
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

# --------------------------- Subcommands ---------------------------------------------

# TODO: expand.
_aes_help = """Run an AES wrapper."""


@app.command(name="AES", no_args_is_help=True, help=_aes_help)
@app.command(name="aes", no_args_is_help=True, help=_aes_help, hidden=True)
def aes(
    # language: Annotated[AES.Wrapper, _language],
    wrapper: Annotated[str, typer.Argument(metavar="FILE")],
    mode: Annotated[AES.Mode, _mode],
    key_length: Annotated[
        AesStrKeyLength,
        typer.Argument(help="The length of the key in bits. Use 0 for any."),
    ] = AesStrKeyLength.ALL,
    iv_length: Annotated[
        int,
        typer.Option(
            help=(
                "The length of the IV, if the implementation only supports"
                " a specific length"
            )
        ),
    ] = 0,
    compliance: Annotated[bool, _compliance] = True,
    resilience: Annotated[bool, _resilience] = False,
    encrypt: Annotated[bool, _encrypt] = True,
    decrypt: Annotated[bool, _decrypt] = True,
    filename: Annotated[str, _filename] = "",
    no_save: Annotated[bool, _no_save] = False,
):
    """Runs an AES wrapper.

    Args:
        wrapper: The wrapper to test.
        mode: The mode of operation.
        key_length: The length of the keys to use in bits.
        iv_length: The length of the IV that can be tested.
        compliance: Whether to use compliance test vectors.
        resilience: Whether to use resilience test vectors.
        encrypt: Whether to test encryption.
        decrypt: Whether to test decryption.
        filename: Name of the file to save results.
        no_save: Do not save results or prompt the user.

    Notes:
        - no_encrypt and no_decrypt should not be True at the same time.
        - no_compliance and no_resilience should not be True at the same time.
    """
    if not encrypt and not decrypt:  # pragma: no cover (not needed)
        console.print("--no-encrypt and --no-decrypt used, no operation selected!")
        raise typer.Exit(1)
    if not compliance and not resilience:  # pragma: no cover (not needed)
        console.print(
            "--no-compliance and --no-resilience used, no test vectors to use!"
        )
        raise typer.Exit(1)

    try:
        results = AES.run_wrapper(
            Path(wrapper),
            mode,
            AES.KeyLength(int(key_length)),
            compliance=compliance,
            resilience=resilience,
            encrypt=encrypt,
            decrypt=decrypt,
            iv_length=iv_length,
        )
    except (SubprocessError, ValueError, FileNotFoundError) as error:
        logger.error(error)
        raise typer.Exit(1) from error
    if console.process_results(results, filename, no_save):
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
    if console.process_results(results, filename, no_save):
        raise typer.Exit(0)
    else:
        raise typer.Exit(1)


# TODO: expand.
_kyber_help = "Run a Kyber wrapper"


@app.command(name="Kyber", no_args_is_help=True, help=_kyber_help)
@app.command(name="kyber", no_args_is_help=True, help=_kyber_help, hidden=True)
def kyber(
    language: Annotated[Kyber.Wrapper, _language],
    parameter_set: Annotated[
        Kyber.Paramset,
        typer.Argument(help="The parameter set.", case_sensitive=False),
    ],
    encapsulate: Annotated[
        bool,
        typer.Option(
            "--encapsulate/--no-encapsulate",
            help="Whether to test the encapsulation function.",
        ),
    ] = True,
    decapsulate: Annotated[
        bool,
        typer.Option(
            "--decapsulate/--no-decapsulate",
            help="Whether to test the decapsulation function.",
        ),
    ] = True,
    filename: Annotated[str, _filename] = "",
    no_save: Annotated[bool, _no_save] = False,
):
    """Runs a Kyber wrapper.

    Args:
        language: The language of the wrapper to run.
        parameter_set: The Kyber parameter set to use.
        encapsulate: Whether to test the encapsulation function.
        decapsulate: Whether to test the decapsulation function.
        filename: Name of the file to save results.
        no_save: Do not save results or prompt the user.
    """
    if not encapsulate and not decapsulate:  # pragma: no cover (not needed)
        console.print(
            "--no-encapsulate and --no-decapsulate used, no function to test."
        )
        raise typer.Exit(1)
    try:
        results = Kyber.run_wrapper(language, parameter_set, encapsulate, decapsulate)
    except Exception as error:
        console.print(error)
        raise typer.Exit(1) from error
    if console.process_results(results, filename, no_save):
        raise typer.Exit(0)
    else:
        raise typer.Exit(1)


# TODO: expand.
_dilithium_help = "Run a Dilithium wrapper."


@app.command(name="Dilithium", no_args_is_help=True, help=_dilithium_help)
@app.command(name="dilithium", no_args_is_help=True, help=_dilithium_help, hidden=True)
def dilithium(
    language: Annotated[Dilithium.Wrapper, _language],
    parameter_set: Annotated[
        Dilithium.Paramset,
        typer.Argument(help="The parameter set.", case_sensitive=False),
    ],
    sign: Annotated[bool, _sign] = True,
    verify: Annotated[bool, _verify] = True,
    filename: Annotated[str, _filename] = "",
    no_save: Annotated[bool, _no_save] = False,
):
    """Runs a Dilithium wrapper.

    Args:
        language: The language of the wrapper to run.
        parameter_set: The Dilithium parameter set to use.
        sign: Whether to test the signing function.
        verify: Whether to test the verifying function.
        filename: Name of the file to save results.
        no_save: Do not save results or prompt the user.
    """
    try:
        results = Dilithium.run_wrapper(language, parameter_set, sign, verify)
    except Exception as error:
        console.print(error)
        raise typer.Exit(1) from error
    if console.process_results(results, filename, no_save):
        raise typer.Exit(0)
    else:
        raise typer.Exit(1)


# TODO: expand.
_sha_help = "Run a SHA wrapper."


@app.command(name="SHA", no_args_is_help=True, help=_sha_help)
@app.command(name="sha", no_args_is_help=True, help=_sha_help, hidden=True)
def sha(
    wrapper: Annotated[str, typer.Argument(metavar="FILE")],
    algorithm: Annotated[
        SHA.Algorithm,
        typer.Argument(
            help="The SHA algorithm to test.", case_sensitive=False, show_default=False
        ),
    ],
    orientation: Annotated[
        SHA.Orientation,
        typer.Argument(
            help="The orientation of the implementation, either bit- or byte-oriented.",
            case_sensitive=False,
        ),
    ] = SHA.Orientation.BYTE,
    filename: Annotated[str, _filename] = "",
    no_save: Annotated[bool, _no_save] = False,
):
    """Runs a SHA wrapper.

    Args:
        wrapper: The wrapper to test.
        algorithm: The SHA algorithm to test.
        orientation: The orientation of the implementation, either bit- or
            byte-oriented.
        filename: Name of the file to save results.
        no_save: Do not save results or prompt the user.
    """
    try:
        results = SHA.run_wrapper(Path(wrapper), algorithm, orientation)
    except ValueError as error:
        logger.error(error)
        raise typer.Exit(1) from error
    if console.process_results(results, filename, no_save):
        raise typer.Exit(0)
    else:
        raise typer.Exit(1)


# TODO: expand.
_shake_help = "Run a SHAKE wrapper."


@app.command(name="SHAKE", no_args_is_help=True, help=_shake_help)
@app.command(name="shake", no_args_is_help=True, help=_shake_help, hidden=True)
def shake(
    language: Annotated[SHAKE.Wrapper, _language],
    algorithm: Annotated[
        SHAKE.Algorithm,
        typer.Argument(help="The XOF algorithm to test.", case_sensitive=False),
    ],
    orientation: Annotated[
        SHAKE.Orientation,
        typer.Argument(
            help="The orientation of the implementation, either bit- or byte-oriented.",
            case_sensitive=False,
        ),
    ],
    filename: Annotated[str, _filename] = "",
    no_save: Annotated[bool, _no_save] = False,
):
    """Runs a SHA wrapper.

    Args:
        language: The language of the wrapper to run.
        algorithm: The SHAKE algorithm to test.
        orientation: The orientation of the implementation, either bit- or
            byte-oriented.
        filename: Name of the file to save results.
        no_save: Do not save results or prompt the user.
    """
    try:
        results = SHAKE.run_wrapper(language, algorithm, orientation)
    except ValueError as error:
        logger.error(error)
        raise typer.Exit(1) from error
    if console.process_results(results, filename, no_save):
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
    """
    try:
        results = RSASSA.run_wrapper(language, scheme, sha, mgf_sha, sign, verify)
    except Exception as error:
        logger.error(error)
        raise typer.Exit(1) from error
    if console.process_results(results, filename, no_save):
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
):
    """Runs a RSAES wrapper.

    Args:
        language: The language of the wrapper to run.
        scheme: The RSA scheme to test.
        sha: The SHA to use in RSAES-OAEP.
        mgf_sha: The SHA to use with MGF1 in RSAES-OAEP.
        filename: Name of the file to save results.
        no_save: Do not save results or prompt the user.
    """
    try:
        results = RSAES.run_rsaes_wrapper(language, scheme, sha, mgf_sha)
    except Exception as error:
        logger.error(error)
        raise typer.Exit(1) from error
    if console.process_results(results, filename, no_save):
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
    if console.process_results(results, filename, no_save):
        raise typer.Exit(0)
    else:
        raise typer.Exit(1)


# TODO: expand.
_hmac_help = """Run an HMAC wrapper."""


@app.command(name="HMAC", no_args_is_help=True, help=_hmac_help)
@app.command(name="hmac", no_args_is_help=True, help=_hmac_help, hidden=True)
def hmac(
    language: Annotated[HMAC.Wrapper, _language],
    hash_function: Annotated[
        HMAC.Hash,
        typer.Argument(
            help="The hash function to use with HMAC",
            show_default=False,
            case_sensitive=False,
        ),
    ],
    compliance: Annotated[bool, _compliance] = True,
    resilience: Annotated[bool, _resilience] = False,
    filename: Annotated[str, _filename] = "",
    no_save: Annotated[bool, _no_save] = False,
):
    """Runs an HMAC wrapper."""
    try:
        results = HMAC.run_wrapper(
            language, hash_function, compliance, resilience, False, False
        )
    except Exception as error:
        console.print(error)
        raise typer.Exit(1) from error
    if console.process_results(results, filename, no_save):
        raise typer.Exit(0)
    else:
        raise typer.Exit(1)


_ecdh_help = "Run an ECDH wrapper."


@app.command(name="ECDH", no_args_is_help=True, help=_ecdh_help)
@app.command(name="ecdh", no_args_is_help=True, help=_ecdh_help, hidden=True)
def ecdh(
    lang: Annotated[
        ECDH.Wrapper,
        typer.Argument(
            metavar="LANG",
            help=(
                "The language of the wrapper. Possible values are: "
                f"{', '.join([str(lang) for lang in ECDH.Wrapper])}."
            ),
            show_default=False,
            case_sensitive=False,
        ),
    ],
    curve: Annotated[
        ECDH.Curve,
        typer.Argument(
            metavar="CURVE",
            help=(
                "The elliptic curve to use. Possible values are: "
                f"{', '.join([str(c) for c in ECDH.Curve])}."
            ),
            show_default=False,
            case_sensitive=False,
        ),
    ],
    wrapper: Annotated[str, typer.Argument(metavar="FILE")] = "ECDH_wrapper.py",
    compliance: Annotated[bool, _compliance] = True,
    resilience: Annotated[bool, _resilience] = False,
    filename: Annotated[str, _filename] = "",
    no_save: Annotated[bool, _no_save] = False,
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
    """
    try:
        results = ECDH.run_wrapper(Path(wrapper), lang, curve, compliance, resilience)
    except (FileNotFoundError, ModuleNotFoundError) as error:
        raise typer.Exit(1) from error
    if console.process_results(results, filename, no_save):
        raise typer.Exit(0)
    else:
        raise typer.Exit(1)
