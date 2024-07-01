"""The CRYSTALS-Kyber primitive."""

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
from cffi import FFI
from rich.progress import track

from crypto_condor.primitives.common import (
    DebugInfo,
    Results,
    ResultsDict,
    TestType,
    get_appdata_dir,
)
from crypto_condor.vectors.Kyber import KyberVectors, Paramset

# --------------------------- Module --------------------------------------------------

logger = logging.getLogger(__name__)


def __dir__():  # pragma: no cover
    return [
        # Enums
        Wrapper.__name__,
        # Protocols
        Encapsulate.__name__,
        Decapsulate.__name__,
        # Dataclasses
        # Functions
        run_wrapper.__name__,
        test_encapsulate.__name__,
        test_decapsulate.__name__,
        # Imported
        Paramset.__name__,
    ]


# --------------------------- Kyber C implementation ----------------------------------
_LIB_DIR: Path | None = None


def _get_lib_dir() -> Path:
    """Returns the path to the directory containing the Kyber shared libraries.

    If the directory is not found, it extracts the source files from the bundled zip
    file. If the shared libraries are not found, it compiles them.
    """
    lib_dir = get_appdata_dir() / "Kyber"
    libs = [f"libpqcrystals_{str(pset).lower()}_ref.so" for pset in Paramset]
    rsc = resources.files("crypto_condor") / "primitives/_kyber"
    install = False

    if not lib_dir.is_dir():
        _msg = (
            "Kyber directory not found:"
            " crypto-condor uses the reference implementation of Kyber,"
            " which has to be compiled and installed locally"
        )
        logger.warning(_msg)
        logger.warning("Installation will be done at %s", str(lib_dir))
        lib_dir.mkdir(0o755, parents=True, exist_ok=True)
        shutil.copyfile(str(rsc / "README.md"), lib_dir / "README.md")
        install = True

    files = [file.name for file in lib_dir.iterdir()]
    if any([lib not in files for lib in libs]):
        install = True

    if install:
        lib_zip = rsc / "kyber.zip"
        with tempfile.TemporaryDirectory() as tmpdir:
            with zipfile.ZipFile(str(lib_zip)) as myzip:
                myzip.extractall(tmpdir)
            try:
                subprocess.run(
                    ["make", "shared"],
                    cwd=Path(tmpdir) / "kyber/ref",
                    check=True,
                    capture_output=True,
                    timeout=15.0,
                )
            except subprocess.CalledProcessError:
                logger.critical("Failed to compile Kyber")
                raise
            for lib in libs:
                src = Path(tmpdir) / "kyber/ref" / lib
                shutil.move(src, lib_dir)
            logger.info("Kyber implementation installed")

    global _LIB_DIR
    _LIB_DIR = lib_dir

    return lib_dir


# --------------------------- Enums ---------------------------------------------------


class Wrapper(strenum.StrEnum):
    """Available wrappers."""

    PYTHON = "Python"


# --------------------------- Protocols -----------------------------------------------


class Encapsulate(Protocol):
    """Represents a function that encapsulates secrets with Kyber."""

    def __call__(self, public_key: bytes) -> tuple[bytes, bytes]:
        """Generates and encapsulates a shared secret.

        Args:
            public_key: The public key to encapsulate the secret with.

        Returns:
            A tuple (ct, ss) containing the shared secret (ss) and ciphertext (ct).
        """
        ...  # pragma: no cover (protocol)


class Decapsulate(Protocol):
    """Represents a function that decapsulates secrets with Kyber."""

    def __call__(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        """Decapsulates a shared secret.

        Args:
            secret_key: The secret key to use.
            ciphertext: The encapsulated shared secret.

        Returns:
            The decapsulated shared secret.
        """
        ...  # pragma: no cover (protocol)


# --------------------------- Dataclasses ---------------------------------------------


@attrs.define
class EncapData:
    """Debug data for :func:`test_encapsulate`.

    Args:
        info: Common debug info, see :class:`crypto_condor.primitives.common.DebugInfo`.
        pk: The public key.
        ct: The resulting ciphertext.
        ss: The generated shared secret.
        decap_ss: The shared secret decapsulated by the internal function.
    """

    info: DebugInfo
    pk: bytes
    ct: bytes | None = None
    ss: bytes | None = None
    decap_ss: bytes | None = None

    def __str__(self) -> str:
        """Returns a string representation."""
        s = f"""{str(self.info)}
pk = {self.pk.hex()}
returned ct = {self.ct.hex() if self.ct else '<none>'}
returned ss = {self.ss.hex() if self.ss else '<none>'}
decapsulated ss = {self.decap_ss.hex() if self.decap_ss else '<none>'}
"""
        return s


@attrs.define
class DecapData:
    """Debug data for :func:`test_decapsulate`.

    Args:
        info: Common debug info, see :class:`crypto_condor.primitives.common.DebugInfo`.
        sk: The secret key.
        ct: The ciphertext.
        ss: The expected shared secret.
        res_ss: The decapsulated shared secret.
    """

    info: DebugInfo
    sk: bytes
    ct: bytes
    ss: bytes
    res_ss: bytes | None

    def __str__(self) -> str:
        """Returns a string representation."""
        s = f"""{str(self.info)}
sk = {self.sk.hex()}
ct = {self.ct.hex()}
ss = {self.ss.hex()}
resulting_ss = {self.res_ss.hex() if self.res_ss else '<none>'}
"""
        return s


# --------------------------- Internal ------------------------------------------------


def _encapsulate(paramset: Paramset, public_key: bytes) -> tuple[bytes, bytes]:
    """Generates a random secret and encapsulates it.

    Uses the reference implementation of Kyber.

    Args:
        paramset: The Kyber parameter set to use.
        public_key: The public key to use for encapsulating the generated secret.

    Returns:
        A tuple (ct, ss) containing the generated secret ss and the ciphertext ct.
    """
    fname = f"pqcrystals_{str(paramset).lower().replace('-', '_')}_ref_enc"
    ffi = FFI()
    ffi.cdef(
        f"""
        int {fname}(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
        """
    )

    lib_dir = _LIB_DIR or _get_lib_dir()
    lib_path = lib_dir / f"libpqcrystals_{str(paramset).lower()}_ref.so"
    lib = ffi.dlopen(str(lib_path.absolute()))

    pk = ffi.new("uint8_t[]", public_key)
    ct = ffi.new(f"uint8_t[{paramset.ct_size}]")
    ss = ffi.new("uint8_t[32]")

    # Hacky way of getting the function: cffi does not seem to allow calling functions
    # dynamically like ctypes with lib[function]. lib should only contain the function
    # cdef'd above so we use dir to get the attributes of lib.
    func = getattr(lib, dir(lib)[0])
    func(ct, ss, pk)

    return bytes(ct), bytes(ss)


def _decapsulate(paramset: Paramset, secret_key: bytes, ciphertext: bytes) -> bytes:
    """Decapsulates a ciphertext containing a generated secret.

    Uses the reference implementation of Kyber.

    Args:
        paramset: The Kyber parameter set to use.
        secret_key: The secret key to use for decapsulating the ciphertext.
        ciphertext: A ciphertext returned by :func:`_encapsulate`.

    Returns:
        The generated secret.
    """
    fname = f"pqcrystals_{str(paramset).lower().replace('-', '_')}_ref_dec"
    ffi = FFI()
    ffi.cdef(
        f"""
        int {fname}(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
        """
    )

    lib_dir = _LIB_DIR or _get_lib_dir()
    lib_path = lib_dir / f"libpqcrystals_{str(paramset).lower()}_ref.so"
    lib = ffi.dlopen(str(lib_path.absolute()))

    sk = ffi.new("uint8_t[]", secret_key)
    ct = ffi.new("uint8_t[]", ciphertext)
    ss = ffi.new("uint8_t[32]")

    # Hacky way of getting the function: cffi does not seem to allow calling functions
    # dynamically like ctypes with lib[function]. lib should only contain the function
    # cdef'd above so we use dir to get the attributes of lib.
    func = getattr(lib, dir(lib)[0])
    func(ss, ct, sk)

    return bytes(ss)


# --------------------------- Test functions ------------------------------------------


def test_encapsulate(encapsulate: Encapsulate, paramset: Paramset) -> Results | None:
    """Tests encapsulation using NIST test vectors.

    The generation of the shared secret is random, so we cannot simply compare the
    ciphertext returned by ``encapsulate`` with the test vector's ciphertext. Instead,
    we call ``encapsulate``, then decapsulate the ciphertext with the internal
    decapsulation function, and compare the resulting shared secret with the one
    returned by ``encapsulate``. If they match, we consider it a pass.

    .. attention::

        crypto-condor uses the reference C implementation of Kyber: it comes bundled
        with the package, but has to be compiled and installed locally. This is done
        automatically when the internal implementation is needed, but if the compilation
        fails this test cannot be run. You can report a problem by opening an issue.

    Args:
        encapsulate: The function to test.
        paramset: The parameter set to test the implementation on.

    Returns:
        The results of testing the implementation, or None if the internal decapsulation
        function can't run.
    """
    results = Results(
        "Kyber",
        "test_encapsulate",
        (
            "Encapsulates with the given function, decapsulates the ciphertext,"
            " and compares the shared secrets."
        ),
        {"paramset": paramset},
    )

    vectors = KyberVectors.load(paramset)
    for test in track(vectors.tests):
        info = DebugInfo(test.count, TestType.VALID, ["Compliance"])
        try:
            ct, ss = encapsulate(test.pk)
        except Exception:
            logger.debug("Error running user-defined encapsulate", exc_info=True)
            results.add(EncapData(info, test.pk))
            continue
        try:
            res_ss = _decapsulate(paramset, test.sk, ct)
        except subprocess.CalledProcessError:
            logger.error("Can't run the internal decapsulation, stopping test")
            return None
        except Exception:
            logger.debug("Kyber.decaps error", exc_info=True)
            results.add(DecapData(info, test.sk, ct, ss, None))
            continue

        if ss == res_ss:
            info.result = True
        else:
            info.error_msg = "Ciphertext does not match the shared secret"
        results.add(EncapData(info, test.pk, ct, ss, res_ss))

    return results


def test_decapsulate(decapsulate: Decapsulate, paramset: Paramset) -> Results:
    """Tests decapsulation with NIST test vectors.

    Decapsulates a ciphertext with the given function and compares with the expected
    shared secret. The test passes if the secrets match.

    Args:
        decapsulate: The function to test.
        paramset: The parameter set to test the implementation on.

    Return:
        The results of testing the implementation.
    """
    results = Results(
        "Kyber",
        "test_decapsulate",
        (
            "Decapsulates ciphertexts and compares the resulting shared secrets with"
            " the test vectors'."
        ),
        {"paramset": paramset},
    )

    vectors = KyberVectors.load(paramset)
    for test in vectors.tests:
        info = DebugInfo(test.count, TestType.VALID, ["Compliance"])
        try:
            res_ss = decapsulate(test.sk, test.ct)
        except Exception as error:
            logger.debug("Kyber.decap error: %s", str(error))
            results.add(DecapData(info, test.sk, test.ct, test.ss, None))
        if res_ss == test.ss:
            info.result = True
        else:
            info.error_msg = "Decapsulate returns wrong shared secret"
        results.add(DecapData(info, test.sk, test.ct, test.ss, res_ss))

    return results


# --------------------------- Runners -------------------------------------------------


def _run_python(parameter_set: Paramset, run_enc: bool, run_dec: bool) -> ResultsDict:
    """Runs the Python Kyber wrapper.

    Args:
        parameter_set: The parameter set to run with.
        run_enc: Whether to use the encapsulation function.
        run_dec: Whether to use the decapsulation function.

    Returns:
        A dictionary of results, one result for encapsulation, one for decapsulation.
        The keys are "encap" and "decap".
    """
    wrapper = Path.cwd() / "kyber_wrapper.py"
    if not wrapper.is_file():
        raise FileNotFoundError("Can't find kyber_wrapper.py in the current directory.")

    logger.info("Running Python Kyber wrapper")

    # Add CWD to the path, at the beginning in case this is called more than
    # once, since the previous CWD would have priority.
    sys.path.insert(0, str(Path.cwd()))

    # Before importing the wrapper we check if it's already in the loaded
    # modules, in which case we want to reload it or we would be testing the
    # wrapper loaded previously.
    imported = "kyber_wrapper" in sys.modules.keys()

    # Import it normally.
    try:
        kyber_wrapper = importlib.import_module("kyber_wrapper")
    except ModuleNotFoundError as error:
        logger.debug(error)
        raise FileNotFoundError("Can't load the wrapper!") from error

    # Then reload it if necessary.
    if imported:
        logger.debug("Reloading the Kyber Python wrapper")
        kyber_wrapper = importlib.reload(kyber_wrapper)

    results_dict = ResultsDict()
    if run_enc:
        res = test_encapsulate(kyber_wrapper.encapsulate, parameter_set)
        if res is not None:
            results_dict["encap"] = res
    if run_dec:
        results_dict["decap"] = test_decapsulate(
            kyber_wrapper.decapsulate, parameter_set
        )

    # To de-clutter the path, remove the CWD.
    sys.path.remove(str(Path.cwd()))

    return results_dict


def run_wrapper(
    language: Wrapper,
    parameter_set: Paramset,
    run_encapsulate: bool,
    run_decapsulate: bool,
) -> ResultsDict:
    """Runs the corresponding wrapper.

    Args:
        language: The language of the wrapper to run.
        parameter_set: The parameter set to use.
        run_encapsulate: Whether to run the encapsulation function.
        run_decapsulate: Whether to run the decapsulation function.

    Returns:
        A dictionary of results, one result for encapsulation, one for decapsulation.
        The keys are ``encap`` and ``decap``.
    """
    match language:
        case Wrapper.PYTHON:
            return _run_python(parameter_set, run_encapsulate, run_decapsulate)
        case _:  # pragma: no cover (mypy)
            return ResultsDict()


if __name__ == "__main__":
    # Install Kyber when called as a script.
    _get_lib_dir()
