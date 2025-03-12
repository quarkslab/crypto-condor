"""Module for testing ML-KEM implementations."""

import importlib
import json
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
import cffi
import strenum
from rich.progress import track

from crypto_condor.primitives.common import (
    Results,
    ResultsDict,
    TestInfo,
    TestType,
    get_appdata_dir,
)
from crypto_condor.vectors._mlkem.mlkem_pb2 import MlkemTest, MlkemVectors

# --------------------------- Module --------------------------------------------------

logger = logging.getLogger(__name__)


def __dir__():  # pragma: no cover
    return [
        # Enums
        Paramset.__name__,
        # Protocols
        Encaps.__name__,
        Decaps.__name__,
        # Test functions
        test_encaps.__name__,
        test_decaps.__name__,
        # Runners
        run_python_wrapper.__name__,
    ]


# --------------------------- Enums ---------------------------------------------------


class Paramset(strenum.StrEnum):
    """The parameter sets for ML-KEM."""

    def __new__(cls, value):
        """Override __new__ to add custom properties."""
        member = str.__new__(cls, value)
        member._value_ = value
        match value:
            case "ML-KEM-512":
                member._sk_size_ = 1632
                member._pk_size_ = 800
                member._ct_size_ = 768
            case "ML-KEM-768":
                member._sk_size_ = 2400
                member._pk_size_ = 1184
                member._ct_size_ = 1088
            case "ML-KEM-1024":
                member._sk_size_ = 3168
                member._pk_size_ = 1568
                member._ct_size_ = 1568
        return member

    @property
    def sk_size(self):
        """The secret key size of the parameter set in bytes."""
        return self._sk_size_

    @property
    def pk_size(self):
        """The public key size of the parameter set in bytes."""
        return self._pk_size_

    @property
    def ct_size(self):
        """The ciphertext size of the parameter set in bytes."""
        return self._ct_size_

    MLKEM512 = "ML-KEM-512"
    MLKEM768 = "ML-KEM-768"
    MLKEM1024 = "ML-KEM-1024"


class Wrapper(strenum.StrEnum):
    """Supported wrapper languages."""

    PYTHON = "Python"


# --------------------------- Reference implementation --------------------------------
SHARED_LIB_DIR: Path | None = None


def _get_shared_lib_dir() -> Path:
    """Returns the path to the directory containing the shared libraries.

    crypto-condor bundles the reference implementation of ML-KEM
    (https://github.com/pq-crystals/kyber), which has to be copied, compiled, and
    installed in the user's machine.

    This function checks if the resulting shared libraries are already present in the
    user's app data directory. If not, the directory is created, and the implementation
    installed from the bundled zip file.
    """
    lib_dir = get_appdata_dir() / "MLKEM"
    libs = {
        "libpqcrystals_kyber512_ref.so": "ML-KEM-512-ref.so",
        "libpqcrystals_kyber768_ref.so": "ML-KEM-768-ref.so",
        "libpqcrystals_kyber1024_ref.so": "ML-KEM-1024-ref.so",
    }
    rsc = resources.files("crypto_condor") / "primitives/_mlkem"
    install = False

    if not lib_dir.is_dir():
        _msg = (
            "ML-KEM directory not found:"
            " crypto-condor uses the reference implementation of ML-KEM,"
            " which has to be compiled and installed locally"
        )
        logger.warning(_msg)
        logger.warning("Installation will be done at %s", str(lib_dir))
        lib_dir.mkdir(0o755, parents=True, exist_ok=True)
        shutil.copyfile(str(rsc / "README.md"), lib_dir / "README.md")
        install = True

    files = [file.name for file in lib_dir.iterdir()]
    if any([lib not in files for lib in libs.values()]):
        install = True

    if install:
        lib_zip = rsc / "mlkem.zip"
        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                with zipfile.ZipFile(str(lib_zip)) as myzip:
                    myzip.extractall(tmpdir)
            except Exception:
                logger.critical("Failed to unzip mlkem.zip", exc_info=True)
                raise
            try:
                subprocess.run(
                    ["make", "shared"],
                    cwd=Path(tmpdir) / "kyber/ref",
                    check=True,
                    capture_output=True,
                    timeout=15.0,
                )
            except subprocess.CalledProcessError:
                logger.critical("Failed to compile ML-KEM implementation")
                raise
            for lib, dst in libs.items():
                src = Path(tmpdir) / "kyber/ref/lib" / lib
                shutil.move(src, lib_dir / dst)
            logger.info("ML-KEM implementation installed")

    global SHARED_LIB_DIR
    SHARED_LIB_DIR = lib_dir

    return lib_dir


def _keygen(paramset: Paramset) -> tuple[bytes, bytes]:
    """Generates a ML-KEM key pair.

    Args:
        paramset: The parameter set to use.

    Returns:
        A tuple (pk, sk) containing the public and secret key.

    .. attention:: Internal use only

        This implementation is for testing with crypto-condor, and is not exposed for
        production use.
    """
    fname = f"pqcrystals_{str(paramset).replace('ML-KEM-', 'kyber')}_ref_keypair"
    ffi = cffi.FFI()
    ffi.cdef(f"int {fname}(uint8_t *pk, uint8_t *sk);")
    lib_dir = SHARED_LIB_DIR or _get_shared_lib_dir()
    lib_path = lib_dir / f"{str(paramset)}-ref.so"
    lib = ffi.dlopen(str(lib_path.absolute()))

    c_pk = ffi.new(f"uint8_t[{paramset.pk_size}]")
    c_sk = ffi.new(f"uint8_t[{paramset.sk_size}]")
    func = getattr(lib, fname)
    func(c_pk, c_sk)
    return bytes(c_pk), bytes(c_sk)


def _encaps(paramset: Paramset, pk: bytes) -> tuple[bytes, bytes]:
    """Encapsulated using the internal implementation.

    Args:
        paramset: The parameter set to use.
        pk: The public key to encapsulate to.

    Returns:
        A tuple (ct, ss) containing the ciphertext and the shared secret.

    .. attention:: Internal use only

        This implementation is for testing with crypto-condor, and is not exposed for
        production use.
    """
    fname = f"pqcrystals_{str(paramset).replace('ML-KEM-', 'kyber')}_ref_enc"
    ffi = cffi.FFI()
    ffi.cdef(
        f"""
        int {fname}(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
        """
    )

    lib_dir = SHARED_LIB_DIR or _get_shared_lib_dir()
    lib_path = lib_dir / f"{str(paramset)}-ref.so"
    lib = ffi.dlopen(str(lib_path.absolute()))

    c_pk = ffi.new("uint8_t[]", pk)
    c_ct = ffi.new(f"uint8_t[{paramset.ct_size}]")
    c_ss = ffi.new("uint8_t[32]")

    func = getattr(lib, fname)
    func(c_ct, c_ss, c_pk)

    return bytes(c_ct), bytes(c_ss)


def _decaps(paramset: Paramset, sk: bytes, ct: bytes) -> bytes:
    """Decapsulates using the internal implementation.

    Args:
        paramset: The parameter set to use.
        sk: The secret key to decapsulate with.
        ct: The ciphertext to decapsulate.

    Returns:
        The decapsulated shared secret.

    .. attention:: Internal use only

        This implementation is for testing with crypto-condor, and is not exposed for
        production use.
    """
    fname = f"pqcrystals_{str(paramset).replace('ML-KEM-', 'kyber')}_ref_dec"
    ffi = cffi.FFI()
    ffi.cdef(
        f"""
        int {fname}(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
        """
    )

    lib_dir = SHARED_LIB_DIR or _get_shared_lib_dir()
    lib_path = lib_dir / f"{str(paramset)}-ref.so"
    lib = ffi.dlopen(str(lib_path.absolute()))

    c_sk = ffi.new("uint8_t[]", sk)
    c_ct = ffi.new("uint8_t[]", ct)
    c_ss = ffi.new("uint8_t[32]")

    func = getattr(lib, fname)
    func(c_ss, c_ct, c_sk)

    return bytes(c_ss)


# --------------------------- Vectors -------------------------------------------------


def _load_vectors(paramset: Paramset) -> list[MlkemVectors]:
    """Loads vectors for a given parameter set.

    Args:
        paramset: The parameter set to load vectors of.

    Returns:
        A list of vectors.
    """
    vectors_dir = importlib.resources.files("crypto_condor") / "vectors/_mlkem"
    vectors = list()

    sources_file = vectors_dir / "mlkem.json"
    with sources_file.open("r") as file:
        sources = json.load(file)

    for filename in sources.get(str(paramset)):
        vectors_file = vectors_dir / "pb2" / filename
        _vec = MlkemVectors()
        logger.debug("Loading ML-KEM vectors from %s", str(filename))
        try:
            _vec.ParseFromString(vectors_file.read_bytes())
        except Exception:
            logger.error("Failed to load ML-KEM vectors from %s", str(filename))
            logger.debug("Exception caught while loading vectors", exc_info=True)
        vectors.append(_vec)

    return vectors


# --------------------------- Protocols -----------------------------------------------


class Encaps(Protocol):
    """Represents an ML-KEM encapsulation function."""

    def __call__(self, pk: bytes) -> tuple[bytes, bytes]:
        """Generates and encapsulates a shared secret.

        Args:
            pk: The public key to encapsulate the secret with.

        Returns:
            A tuple (ct, ss) containing the shared secret (ss) and ciphertext (ct).
        """
        ...  # pragma: no cover (protocol)


class Decaps(Protocol):
    """Represents an ML-KEM decapsulation function."""

    def __call__(self, sk: bytes, ct: bytes) -> bytes:
        """Decapsulates a shared secret.

        Args:
            sk: The secret key to use.
            ct: The ciphertext to decapsulate.

        Returns:
            The decapsulated shared secret.
        """
        ...  # pragma: no cover (protocol)


# --------------------------- Dataclasses----------------------------------------------


@attrs.define
class EncapsData:
    """Debug data for :func:`test_encaps`.

    Args:
        pk: The public key.
        sk: The secret key.
        ret_ct: The ciphertext returned by the implementation.
        ret_ss: The shared secret returned by the implementation.
    """

    pk: bytes
    sk: bytes
    ret_ct: bytes | None = None
    ret_ss: bytes | None = None

    def __str__(self) -> str:
        """Returns a string representation of the data."""
        return f"""pk = {self.pk.hex()}
sk = {self.sk.hex()}
returned ct = {self.ret_ct.hex() if self.ret_ct is not None else "<none>"}
returned ss = {self.ret_ss.hex() if self.ret_ss is not None else "<none>"}
"""


@attrs.define
class DecapsData:
    """Debug data for :func:`test_decaps`.

    Args:
        sk: The secret key.
        ct: The ciphertext.
        ss: The shared secret.
        ret_ss: The decapsulated shared secret returned by the implementation.
    """

    sk: bytes
    ct: bytes
    ss: bytes
    ret_ss: bytes | None = None

    def __str__(self) -> str:
        """Returns a string representation of the data."""
        return f"""sk = {self.sk.hex()}
ct = {self.ct.hex()}
ss = {self.ss.hex()}
returned ss = {self.ret_ss.hex() if self.ret_ss is not None else "<none>"}
"""


# --------------------------- Test functions ------------------------------------------


def test_encaps(encaps: Encaps, paramset: Paramset) -> ResultsDict:
    """Tests encapsulation.

    ML-KEM encapsulation is not deterministic: it generates a random shared
    secret and encapsulates it using the peer's public key, so crypto-condor
    cannot simply compare the ciphertext returned by the implementation with the
    test vector's ciphertext. Instead, it calls the ``encaps`` method to generate
    a shared secret and ciphertext, decapsulates the ciphertext with its
    internal decapsulation function, and compares the resulting shared secret
    with the one returned by the implementation. The test passes if the secrets
    match.

    .. attention::

        crypto-condor uses the reference C implementation of ML-KEM, which is
        bundled with the package but has to be compiled and installed locally.
        This is done automatically when the internal implementation is needed,
        but if the compilation fails this test cannot be run. Please report
        problems by opening an issue.

    Args:
        encaps: The encapsulation implementation.
        paramset: The parameter set to test.

    Returns:
        A dictionary of results. It is empty if the internal decapsulation failed to
        run, or the implementation raised NotImplementedError.
    """
    param_vectors = _load_vectors(paramset)
    rd = ResultsDict()

    test: MlkemTest
    for vectors in param_vectors:
        results = Results.new("Test ML-KEM encapsulation", ["paramset"])
        results.add_notes(vectors.notes)

        for test in track(
            vectors.tests, rf"\[{paramset}]\[{vectors.source}] Testing encapsulation"
        ):
            info = TestInfo.new_from_test(test, vectors.compliance)
            data = EncapsData(test.pk, test.sk)

            try:
                ret_ct, ret_ss = encaps(test.pk)
            except subprocess.CalledProcessError:
                logger.error(
                    "Can't run the internal ML-KEM decapsulation, stopping test"
                )
                return rd
            except NotImplementedError:
                logger.warning("%s Encaps not implemented, skipped", str(paramset))
                return rd
            except ValueError as error:
                # Potential special case when unpacking the returned value.
                logger.debug(
                    "Caught ValueError, is the implementation returning (ct, ss)?",
                    exc_info=True,
                )
                info.fail(f"Exception raised: {str(error)}", data)
                results.add(info)
                continue
            except Exception as error:
                logger.debug("Caught an exception", exc_info=True)
                info.fail(f"Exception raised: {str(error)}", data)
                results.add(info)
                continue

            data.ret_ct = ret_ct
            data.ret_ss = ret_ss

            # TODO: can this fail? Should we add a try/except?
            ss = _decaps(paramset, test.sk, ret_ct)

            match (ret_ss == ss, test.type):
                case (True, TestType.VALID):
                    info.ok(data)
                case (False, TestType.VALID):
                    info.fail("Shared secrets do not match", data)
                case _:
                    # We currently don't have other type of tests for encaps.
                    pass
            results.add(info)

        rd.add(results, ["paramset"])

    return rd


def test_decaps(decaps: Decaps, paramset: Paramset) -> ResultsDict:
    """Tests decapsulation.

    Uses the given function to decapsulate ciphertexts and compares the results with the
    test vectors' shared secrets. The test passes if the secrets match.

    Args:
        decaps: The decapsulation implementation.
        paramset: The parameter set to test.

    Returns:
        A dictionary of results. It is empty if the internal decapsulation failed to
        run, or the implementation raised NotImplementedError.
    """
    param_vectors = _load_vectors(paramset)
    rd = ResultsDict()

    test: MlkemTest
    for vectors in param_vectors:
        results = Results.new("Test ML-KEM decapsulation", ["paramset"])
        results.add_notes(vectors.notes)

        for test in track(
            vectors.tests, rf"\[{paramset}]\[{vectors.source}] Testing decapsulation"
        ):
            info = TestInfo.new_from_test(test, vectors.compliance)
            data = DecapsData(test.sk, test.ct, test.ss)

            try:
                ret_ss = decaps(test.sk, test.ct)
            except NotImplementedError:
                logger.warning("%s Decaps not implemented, skipped", str(paramset))
                return rd
            except Exception as error:
                logger.debug("Caught an exception", exc_info=True)
                info.fail(f"Exception raised: {str(error)}", data)
                results.add(info)
                continue

            data.ret_ss = ret_ss

            match (ret_ss == test.ss, test.type):
                case (True, TestType.VALID):
                    info.ok(data)
                case (False, TestType.VALID):
                    info.fail("Shared secrets do not match", data)
                case _:
                    # We currently don't have other type of tests for decaps.
                    pass
            results.add(info)

        rd.add(results, ["paramset"])

    return rd


def test_output_encaps(output: Path, paramset: Paramset) -> ResultsDict:
    r"""Tests output of encapsulation.

    To test the output of ML-KEM Encaps(), the secret key is used to decapsulate the
    ciphertext and compare the shared secrets.

    Args:
        output: A path to the output file.
        paramset: The parameter set of the output.

    Returns:
        A dictionary of results.

    Format:
        - One line per operation, separated by newlines ``\n``.
        - Lines starting with ``#`` are considered comments and ignored.
        - Values are written in hexadecimal.
        - Values are separated by forward slashes ``/``.
        - The order of the values is:

        .. code::

            pk/sk/ct/ss

        - Where:
            - ``pk`` is the public encapsulation key.
            - ``sk`` is the secret decapsulation key.
            - ``ct`` is the ciphertext.
            - ``ss`` is the shared secret.
    """
    if not output.is_file():
        raise FileNotFoundError("No output file '%s' found" % str(output))
    with output.open("r") as file:
        lines = file.readlines()

    results = Results.new("Tests the output of ML-KEM Encaps", ["output", "paramset"])
    for index, line in track(enumerate(lines, 1), f"[{str(paramset)}] Testing output"):
        if line.startswith("#"):
            continue
        line = line.strip()
        match line.split("/"):
            case [_pk, _sk, _ct, _ss]:
                pk, sk, ct, ss = map(bytes.fromhex, (_pk, _sk, _ct, _ss))
            case _:
                logger.error("Failed to parse line %d (expected 1 value)" % index)
                continue

        info = TestInfo.new(index, TestType.VALID, ["UserInput"])
        data = EncapsData(pk, sk, ct, ss)
        try:
            ret_ss = _decaps(paramset, sk, ct)
        except Exception:
            logger.debug("Failed to decapsulate", exc_info=True)
            info.fail("Error verifying the signature", data)
            results.add(info)
            continue

        if ret_ss == ss:
            info.ok(data)
        else:
            info.fail("Shared secrets do not match", data)
        results.add(info)

    rd = ResultsDict()
    rd.add(results, ["output", "paramset"])
    return rd


# --------------------------- Runners -------------------------------------------------


def run_python_wrapper(
    wrapper: Path, compliance: bool, resilience: bool
) -> ResultsDict:
    """Runs a ML-KEM Python wrapper.

    Args:
        wrapper: A path to the wrapper to run. Must be a Python program.
        compliance: Whether to use compliance test vectors.
        resilience: Whether to use resilience test vectors.

    Returns:
        A dictionary of results.
    """
    logger.info("Running Python ML-KEM wrapper: '%s'", str(wrapper.name))
    sys.path.insert(0, str(wrapper.parent.absolute()))
    already_imported = wrapper.stem in sys.modules.keys()
    try:
        mlkem_wrapper = importlib.import_module(wrapper.stem)
    except ModuleNotFoundError as error:
        logger.error("Can't import wrapper: '%s'", str(error))
        raise
    if already_imported:
        logger.debug("Reloading ML-KEM wrapper: '%s'", wrapper.stem)
        mlkem_wrapper = importlib.reload(mlkem_wrapper)

    rd = ResultsDict()
    for symbol in dir(mlkem_wrapper):
        match symbol.split("_"):
            case ["CC", "MLKEM", _pset, ("encaps" | "decaps") as op]:
                logger.info("Found CC_MLKEM function '%s'", symbol)
                try:
                    paramset = Paramset(f"ML-KEM-{_pset}")
                except ValueError:
                    logger.error("Unknown parameter set ML-KEM-%s for ML-KEM", _pset)
                    continue
                if op == "encaps":
                    rd |= test_encaps(getattr(mlkem_wrapper, symbol), paramset)
                else:
                    rd |= test_decaps(getattr(mlkem_wrapper, symbol), paramset)
            case ["CC", "MLKEM", *_]:
                logger.warning("Ignored unknown CC_MLKEM symbol %s", symbol)
            case _:
                pass

    return rd


# --------------------------- Harness -------------------------------------------------


def _test_harness_encaps(
    ffi: cffi.FFI, lib, function: str, paramset: Paramset
) -> ResultsDict:
    """Tests a harness for encapsulation.

    Args:
        ffi: The FFI instance.
        lib: The dlopen'd library.
        function: The name of the function to test.
        paramset: The function's parameter set.

    Returns:
        The results returned by :func:`test_encaps`.
    """
    logger.info("Testing harness function %s", function)

    ffi.cdef(
        f"""void {function}(uint8_t *ct, size_t ctlen,
                            uint8_t *ss, size_t sslen,
                            const uint8_t *pk, size_t pklen);"""
    )
    encap = getattr(lib, function)

    # Object sizes are known in advance so we can create the type.
    c_ct = ffi.new(f"uint8_t[{paramset.ct_size}]")
    c_ss = ffi.new("uint8_t[32]")

    def _encap(pk: bytes):
        c_pk = ffi.new(f"uint8_t[{paramset.pk_size}]", pk)
        encap(c_ct, paramset.ct_size, c_ss, 32, c_pk, paramset.pk_size)
        return (bytes(c_ct), bytes(c_ss))

    return test_encaps(_encap, paramset)


def _test_harness_decaps(
    ffi: cffi.FFI, lib, function: str, paramset: Paramset
) -> ResultsDict:
    """Tests a harness for decapsulation.

    Args:
        ffi: The FFI instance.
        lib: The dlopen'd library.
        function: The name of the function to test.
        paramset: The function's parameter set.

    Returns:
        The results returned by :func:`test_decaps`.
    """
    logger.info("Testing harness function %s", function)

    ffi.cdef(
        f"""void {function}(uint8_t *ss, size_t sslen,
                          const uint8_t *ct, size_t ctlen,
                          const uint8_t *sk, size_t sklen);"""
    )
    decap = getattr(lib, function)

    # Object sizes are known in advance so we can create the type.
    c_ss = ffi.new("uint8_t[32]")

    def _decap(sk: bytes, ct: bytes):
        c_sk = ffi.new(f"uint8_t[{paramset.sk_size}]", sk)
        c_ct = ffi.new(f"uint8_t[{paramset.ct_size}]", ct)
        decap(c_ss, 32, c_ct, paramset.ct_size, c_sk, paramset.sk_size)
        return bytes(c_ss)

    return test_decaps(_decap, paramset)


def test_lib(
    ffi: cffi.FFI, lib, functions: list[str], compliance: bool, resilience: bool
) -> ResultsDict:
    """Tests functions from a shared library.

    Args:
        ffi:
            The FFI instance.
        lib:
            The dlopen'd library.
        functions:
            A list of CC_Kyber functions to test.
        compliance:
            Whether to use compliance test vectors.
        resilience:
            Whether to use resilience test vectors.
    """
    logger.info("Found harness functions %s", ", ".join(functions))

    rd = ResultsDict()

    for function in functions:
        match function.split("_"):
            case ["CC", "MLKEM", _pset, ("encaps" | "decaps") as op]:
                try:
                    paramset = Paramset(f"ML-KEM-{_pset}")
                except ValueError:
                    logger.error(
                        "Unknown parameter set '%s', skipped function %s",
                        _pset,
                        function,
                    )
                    continue
                if op == "encaps":
                    rd |= _test_harness_encaps(ffi, lib, function, paramset)
                else:
                    rd |= _test_harness_decaps(ffi, lib, function, paramset)
            case _:
                logger.warning("Ignoring unknown CC_MLKEM function %s", function)

    return rd


if __name__ == "__main__":
    _ = _get_shared_lib_dir()
