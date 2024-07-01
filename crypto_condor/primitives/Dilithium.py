"""The CRYSTALS-Dilithium primitive."""

import ctypes
import importlib
import logging
import shutil
import subprocess
import sys
import tempfile
import zipfile
from importlib import resources
from pathlib import Path
from typing import Protocol

import attrs
import strenum
from rich.progress import track

from crypto_condor.primitives.common import (
    DebugInfo,
    Results,
    ResultsDict,
    TestType,
    get_appdata_dir,
)
from crypto_condor.vectors.Dilithium import DilithiumVectors, Paramset

# --------------------------- Module --------------------------------------------------

logger = logging.getLogger(__name__)


def __dir__():  # pragma: no cover
    return [
        # Enums
        Wrapper.__name__,
        # Protocols
        Sign.__name__,
        Verify.__name__,
        # Dataclasses
        # Functions
        run_wrapper.__name__,
        test_sign.__name__,
        test_verify.__name__,
        # Imported
        Paramset.__name__,
    ]


# --------------------------- Dilithium C implementation ------------------------------
_LIB_DIR: Path | None = None


def _get_lib_dir() -> Path:
    """Returns the path to the directory containing the shared libraries.

    If the directory is not found it is created, the libraries compiled and installed.
    """
    lib_dir = get_appdata_dir() / "Dilithium"
    libs = [f"libpqcrystals_{str(pset).lower()}_ref.so" for pset in Paramset]
    rsc = resources.files("crypto_condor") / "primitives/_dilithium"
    install = False

    if not lib_dir.is_dir():
        _msg = (
            "Dilithium directory not found:"
            " crypto-condor uses the reference implementation of Dilithium,"
            " which has to be compiled and installed locally"
        )
        logger.warning(_msg)
        logger.warning("Installation will be done at %s", str(lib_dir))
        lib_dir.mkdir(0o755, parents=True, exist_ok=True)
        shutil.copyfile(str(rsc / "README.md"), lib_dir / "README.md")
        shutil.copyfile(str(rsc / "dilithium.patch"), lib_dir / "dilithium.patch")
        install = True

    files = [file.name for file in lib_dir.iterdir()]
    if any([lib not in files for lib in libs]):
        install = True

    if install:
        lib_zip = rsc / "dilithium.zip"
        with tempfile.TemporaryDirectory() as tmpdir:
            with zipfile.ZipFile(str(lib_zip)) as myzip:
                myzip.extractall(tmpdir)
            # UNIX-y way of testing whether the CPU supports AVX2.
            # try:
            #     output = subprocess.check_output(
            #         ["cc", "-march=native", "-dM", "-E", "-"],
            #         stdin=subprocess.DEVNULL,
            #         timeout=1.0,
            #         text=True,
            #     )
            #     has_avx2 = "AVX2" in output
            # except (FileNotFoundError, subprocess.CalledProcessError):
            #     has_avx2 = False
            # cwd = lib_dir / "avx2" if has_avx2 else lib_dir / "ref"
            try:
                subprocess.run(
                    ["make", "shared"],
                    cwd=Path(tmpdir) / "dilithium/ref",
                    check=True,
                    capture_output=True,
                    timeout=15.0,
                )
            except subprocess.CalledProcessError:
                logger.critical("Failed to compile Dilithium")
                raise
            for lib in libs:
                src = Path(tmpdir) / "dilithium/ref" / lib
                shutil.move(src, lib_dir)
            logger.info("Dilithium implementation installed")

    global _LIB_DIR
    _LIB_DIR = lib_dir

    return lib_dir


# --------------------------- Enums ---------------------------------------------------


class Wrapper(strenum.StrEnum):
    """Available wrappers."""

    PYTHON = "Python"


# --------------------------- Protocols -----------------------------------------------


class Sign(Protocol):
    """Represents a function that signs messages with Dilithium."""

    def __call__(self, secret_key: bytes, message: bytes) -> bytes:
        """Signs a message with Dilithium.

        Args:
            secret_key: The key to use for signing.
            message: The message to sign.

        Returns:
            The signature.
        """


class Verify(Protocol):
    """Represents a function that verifies Dilithium signatures."""

    def __call__(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verifies a Dilithium signature.

        Args:
            public_key: The public part of the key used to sign the message.
            message: The signed message.
            signature: The signature to verify.

        Returns:
            True if the signature is valid for the given key and message.
        """


# --------------------------- Dataclasses ---------------------------------------------


@attrs.define
class SignData:
    """Debug data for :func:`test_sign`.

    Args:
        info: Common debug info, see :class:`crypto_condor.primitives.common.DebugInfo`.
        sk: The secret key.
        msg: The message to sign.
        sig: The expected signature.
        res: The resulting signature.
    """

    info: DebugInfo
    sk: bytes
    msg: bytes
    sig: bytes
    res: bytes

    def __str__(self) -> str:
        """Returns a string representation."""
        s = f"""{str(self.info)}
sk = {self.sk.hex()}
msg = {self.msg.hex()}
sig = {self.sig.hex()}
res = {self.res.hex()}
"""
        return s


@attrs.define
class VerifyData:
    """Debug data for :func:`test_verify`.

    Args:
        info: Common debug info, see :class:`crypto_condor.primitives.common.DebugInfo`.
        pk: The public key.
        msg: The signed message.
        sig: The signature to verify.
    """

    info: DebugInfo
    pk: bytes
    msg: bytes
    sig: bytes

    def __str__(self) -> str:
        """Returns a string representation."""
        s = f"""{str(self.info)}
pk = {self.pk.hex()}
msg = {self.msg.hex()}
sig = {self.sig.hex()}
"""
        return s


# --------------------------- Internal ------------------------------------------------


def _sign(paramset: Paramset, secret_key: bytes, message: bytes) -> bytes:
    """Signs a message.

    Uses the reference implementation.

    Args:
        paramset: The Dilithium parameter set to use.
        secret_key: The key to use for signing.
        message: The message to sign.

    Returns:
        The signed message, which is the concatenation of the signature generated and
        the message.
    """
    n = str(paramset)[-1]
    lib_dir = _LIB_DIR or _get_lib_dir()
    lib_path = lib_dir / f"libpqcrystals_dilithium{n}_ref.so"
    lib = ctypes.cdll.LoadLibrary(str(lib_path.absolute()))

    sign = lib[f"pqcrystals_dilithium{n}_ref"]
    sign.argtypes = [
        ctypes.POINTER(ctypes.c_uint8),  # sm
        ctypes.POINTER(ctypes.c_size_t),  # smlen
        ctypes.POINTER(ctypes.c_uint8),  # m
        ctypes.c_size_t,  # mlen
        ctypes.POINTER(ctypes.c_uint8),  # sk
    ]
    sign.restype = ctypes.c_int

    # len(sm) = len(sig) + len(m), where len(sig) = CRYPTO_BYTES
    _smlen = paramset.sig_size + len(message)
    sm = (ctypes.c_uint8 * _smlen)()
    # Use separate buffers for sm and m -- tried to combine them, didn't work.
    m = (ctypes.c_uint8 * len(message)).from_buffer_copy(message)
    sk = (ctypes.c_uint8 * len(secret_key)).from_buffer_copy(secret_key)
    smlen = ctypes.c_size_t()

    sign(sm, smlen, m, len(message), sk)
    if smlen.value != _smlen:
        # We know smlen in advance so ensure the result is coherent.
        raise ValueError(f"Wrong smlen returned {smlen.value} (expected {_smlen})")

    return bytes(sm)


def _verify(
    paramset: Paramset,
    public_key: bytes,
    signature: bytes,
    message: bytes | None = None,
) -> bool:
    """Verifies a signed message.

    Uses the reference implementation.

    Args:
        paramset: The Dilithium parameter set to use.
        public_key: The public key.
        signature: The signature to verify. If message is None, it is considered to be
            the signed message, i.e. (sig || msg).
        message: The message that was signed.

    Returns:
        True if the signature is valid, False otherwise.

    Raises:
        ValueError: If an error running the verification function occurred.
    """
    n = str(paramset)[-1]
    lib_dir = _LIB_DIR or _get_lib_dir()
    lib_path = lib_dir / f"libpqcrystals_dilithium{n}_ref.so"
    lib = ctypes.cdll.LoadLibrary(str(lib_path.absolute()))

    verify = lib[f"pqcrystals_dilithium{n}_ref_open"]
    verify.argtypes = [
        ctypes.POINTER(ctypes.c_uint8),  # m
        ctypes.POINTER(ctypes.c_size_t),  # mlen
        ctypes.POINTER(ctypes.c_uint8),  # sm
        ctypes.c_size_t,  # smlen
        ctypes.POINTER(ctypes.c_uint8),  # pk
    ]
    verify.restype = ctypes.c_int

    if message is None:
        # signature is the signed message (sig || msg)
        _smlen = len(signature)
        _sm = signature
    else:
        # len(sm) = len(sig) + len(m), where len(sig) = CRYPTO_BYTES
        _smlen = paramset.sig_size + len(message)
        # Get signed message by concatenating signature and message.
        _sm = signature + message
    sm = (ctypes.c_uint8 * _smlen).from_buffer_copy(_sm)
    pk = (ctypes.c_uint8 * len(public_key)).from_buffer_copy(public_key)
    mlen = ctypes.c_size_t()

    # As len(sm) > len(m) and because crypto_sign_open allows it, we can reuse sm.
    return verify(sm, mlen, sm, sm._length_, pk) == 0


# --------------------------- Test functions ------------------------------------------


def test_sign(sign: Sign, parameter_set: Paramset) -> Results:
    """Tests a function that signs with Dilithium.

    Signs messages with the given function and compares to the expected signature.

    Args:
        sign: The function to test, must behave like :protocol:`Sign`.
        parameter_set: The parameter set to test the implementation on.

    Returns:
        The results of testing the given implementation with test vectors generated for
        the NIST submission.
    """
    results = Results(
        "Dilithium",
        "test_sign",
        "Tests a function that signs with Dilithium",
        {"parameter_set": parameter_set},
    )
    vectors = DilithiumVectors.load(parameter_set)
    for test in track(vectors.tests):
        info = DebugInfo(test.count, TestType.VALID, ["Compliance"])
        sm = sign(test.sk, test.msg)
        if sm == test.sm:
            info.result = True
        else:
            info.error_msg = "Wrong signature"
        results.add(SignData(info, test.sk, test.msg, test.sm, sm))
    return results


def test_verify(verify: Verify, parameter_set: Paramset) -> Results:
    """Tests a function that verifies Dilithium signatures.

    Args:
        verify: The function to test, must behave like :protocol:`Verify`.
        parameter_set: The parameter set to test the implementation on.

    Returns:
        The results of testing the given implementation with test vectors generated for
        the NIST submission.
    """
    results = Results(
        "Dilithium",
        "test_verify",
        "Tests a function that verifies Dilithium signatures.",
        {"parameter_set": parameter_set},
    )
    vectors = DilithiumVectors.load(parameter_set)
    for test in track(vectors.tests):
        info = DebugInfo(test.count, TestType.VALID, ["Compliance"])
        sig = test.sm[: parameter_set.sig_size]
        msg = test.sm[parameter_set.sig_size :]
        if verify(test.pk, sig, msg):
            info.result = True
        else:
            info.error_msg = "Valid signature rejected"
        results.add(VerifyData(info, test.pk, msg, sig))
    return results


# --------------------------- Runners -------------------------------------------------


def _run_python(
    parameter_set: Paramset, run_sign: bool, run_verify: bool
) -> ResultsDict:
    """Runs the Python Dilithium wrapper.

    Args:
        parameter_set: The parameter set to run with.
        run_sign: Whether to use the signing function.
        run_verify: Whether to use the verifying function.

    Returns:
        A dictionary of results, one for sign, one for verify. The keys are "sign" and
        "verify".
    """
    wrapper = Path.cwd() / "dilithium_wrapper.py"
    if not wrapper.is_file():
        raise FileNotFoundError(
            "Can't find dilithium_wrapper.py in the current directory."
        )

    print("Running Python Dilithium wrapper")

    # Add CWD to the path, at the beginning in case this is called more than
    # once, since the previous CWD would have priority.
    sys.path.insert(0, str(Path.cwd()))

    # Before importing the wrapper we check if it's already in the loaded
    # modules, in which case we want to reload it or we would be testing the
    # wrapper loaded previously.
    imported = "dilithium_wrapper" in sys.modules.keys()

    # Import it normally.
    try:
        dilithium_wrapper = importlib.import_module("dilithium_wrapper")
    except ModuleNotFoundError as error:
        logger.debug(error)
        raise FileNotFoundError("Can't load the wrapper!") from error

    # Then reload it if necessary.
    if imported:
        logger.debug("Reloading the Dilithium Python wrapper")
        dilithium_wrapper = importlib.reload(dilithium_wrapper)

    results_dict = ResultsDict()

    if run_sign:
        results_dict["sign"] = test_sign(dilithium_wrapper.sign, parameter_set)
    if run_verify:
        results_dict["verify"] = test_verify(dilithium_wrapper.verify, parameter_set)

    # To de-clutter the path, remove the CWD.
    sys.path.remove(str(Path.cwd()))

    return results_dict


def run_wrapper(
    language: Wrapper,
    parameter_set: Paramset,
    run_sign: bool,
    run_verify: bool,
) -> ResultsDict:
    """Runs the corresponding wrapper.

    Args:
        language: The language of the wrapper to run.
        parameter_set: The parameter set to use.
        run_sign: Whether to run the signing function.
        run_verify: Whether to run the verifying function.

    Returns:
        A dictionary of results, one for sign, one for verify. The keys are ``sign`` and
        ``verify``.
    """
    match language:
        case Wrapper.PYTHON:
            return _run_python(parameter_set, run_sign, run_verify)
        case _:
            raise ValueError(f"Unsupported language {language}")


if __name__ == "__main__":
    # Install Dilithium when called as a script.
    _get_lib_dir()
