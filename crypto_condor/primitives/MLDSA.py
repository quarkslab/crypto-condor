"""Module for testing ML-DSA implementations."""

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
from crypto_condor.vectors._mldsa.mldsa_pb2 import MldsaTest, MldsaVectors

# --------------------------- Module --------------------------------------------------

logger = logging.getLogger(__name__)


def __dir__():  # pragma: no cover
    return [
        # Enums
        Paramset.__name__,
        # Protocols
        Sign.__name__,
        Verify.__name__,
        # Test functions
        test_sign.__name__,
        test_verify.__name__,
        # Runners
        run_python_wrapper.__name__,
    ]


# --------------------------- Enums ---------------------------------------------------


class Paramset(strenum.StrEnum):
    """The parameter sets for ML-DSA."""

    def __new__(cls, value):
        """Override __new__ to add custom properties."""
        member = str.__new__(cls, value)
        member._value_ = value
        # Parameter set values from FIPS 204.
        match value:
            case "ML-DSA-44":
                member._pk_size_ = 1312
                member._sk_size_ = 2560
                member._sig_size_ = 2420
                member._dilithium_ = 2
            case "ML-DSA-65":
                member._pk_size_ = 1952
                member._sk_size_ = 4032
                member._sig_size_ = 3309
                member._dilithium_ = 3
            case "ML-DSA-87":
                member._pk_size_ = 2592
                member._sk_size_ = 4896
                member._sig_size_ = 4627
                member._dilithium_ = 5
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
    def sig_size(self):
        """The signature size of the parameter set in bytes."""
        return self._sig_size_

    @property
    def dilithium(self):
        """The equivalent Dilithium parameter set."""
        return self._dilithium_

    ML_DSA_44 = "ML-DSA-44"
    ML_DSA_65 = "ML-DSA-65"
    ML_DSA_87 = "ML-DSA-87"


class Wrapper(strenum.StrEnum):
    """Supported wrapper languages."""

    PYTHON = "Python"


# --------------------------- Reference implementation --------------------------------
SHARED_LIB_DIR: Path | None = None


def _get_shared_lib_dir() -> Path:
    """Returns the path to the directory containing the shared libraries.

    crypto-condor bundles the reference implementation of ML-DSA
    (https://github.com/pq-crystals/dilithium), which has to be copied,
    compiled, and installed in the user's machine.

    This function checks if the resulting shared libraries are already present in the
    user's app data directory. If not, the directory is created, and the implementation
    installed from the bundled zip file.
    """
    lib_dir = get_appdata_dir() / "MLDSA"
    libs = {
        "libpqcrystals_dilithium2_ref.so": "ML-DSA-44-ref.so",
        "libpqcrystals_dilithium3_ref.so": "ML-DSA-65-ref.so",
        "libpqcrystals_dilithium5_ref.so": "ML-DSA-87-ref.so",
    }
    rsc = resources.files("crypto_condor") / "primitives/_mldsa"
    install = False

    if not lib_dir.is_dir():
        _msg = (
            "ML-DSA directory not found:"
            " crypto-condor uses the reference implementation of ML-DSA,"
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
        lib_zip = rsc / "mldsa.zip"
        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                with zipfile.ZipFile(str(lib_zip)) as myzip:
                    myzip.extractall(tmpdir)
            except Exception:
                logger.critical("Failed to unzip mldsa.zip", exc_info=True)
                raise
            try:
                subprocess.run(
                    ["make", "shared"],
                    cwd=Path(tmpdir) / "dilithium/ref",
                    check=True,
                    capture_output=True,
                    timeout=15.0,
                )
            except subprocess.CalledProcessError:
                logger.critical("Failed to compile ML-DSA implementation")
                raise
            for lib, dst in libs.items():
                src = Path(tmpdir) / "dilithium/ref" / lib
                shutil.move(src, lib_dir / dst)
            logger.info("ML-DSA implementation installed")

    global SHARED_LIB_DIR
    SHARED_LIB_DIR = lib_dir

    return lib_dir


def _keygen(paramset: Paramset) -> tuple[bytes, bytes]:
    """Generates a ML-DSA key pair.

    Args:
        paramset: The parameter set to use.

    Returns:
        A tuple (pk, sk) containing the public and secret key.

    .. attention:: Internal use only

        This implementation is for testing with crypto-condor, and is not exposed for
        production use.
    """
    fname = f"pqcrystals_dilithium{paramset.dilithium}_ref_keypair"
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


def _sign(paramset: Paramset, sk: bytes, msg: bytes, ctx: bytes) -> bytes:
    """Signs using the internal implementation.

    Args:
        paramset: The parameter set to use.
        sk: The secret key.
        msg: The message to sign.
        ctx: The context string. Can be an empty bytestring.

    Returns:
        The signature.

    .. attention:: Internal use only

        This implementation is for testing with crypto-condor, and is not exposed for
        production use.
    """
    fname = f"pqcrystals_dilithium{paramset.dilithium}_ref_signature"
    ffi = cffi.FFI()
    ffi.cdef(
        f"""
        int {fname}(uint8_t *sig, uint8_t *siglen,
                    const uint8_t *m, size_t mlen,
                    const uint8_t *ctx, size_t ctxlen,
                    const uint8_t *sk);
        """
    )

    lib_dir = SHARED_LIB_DIR or _get_shared_lib_dir()
    lib_path = lib_dir / f"{str(paramset)}-ref.so"
    lib = ffi.dlopen(str(lib_path.absolute()))

    c_sk = ffi.new("uint8_t[]", sk)
    c_msg = ffi.new("uint8_t[]", msg)
    c_ctx = ffi.new("uint8_t[]", ctx)

    c_sig = ffi.new(f"uint8_t[{paramset.sig_size}]")
    c_siglen = ffi.new("uint8_t *")

    func = getattr(lib, fname)
    func(c_sig, c_siglen, c_msg, len(msg), c_ctx, len(ctx), c_sk)

    return bytes(c_sig)


def _verify(paramset: Paramset, pk: bytes, msg: bytes, sig: bytes, ctx: bytes) -> bool:
    """Verifies a signature with the internal implementation.

    Args:
        paramset: The parameter set to use.
        pk: The public key.
        msg: The message that was signed.
        sig: The signature to verify.
        ctx: The context string.
    """
    fname = f"pqcrystals_dilithium{paramset.dilithium}_ref_verify"
    ffi = cffi.FFI()
    ffi.cdef(
        f"""
        int {fname}(const uint8_t *sig, size_t siglen,
                     const uint8_t *m, size_t mlen,
                     const uint8_t *ctx, size_t ctxlen,
                     const uint8_t *pk);
        """
    )

    lib_dir = SHARED_LIB_DIR or _get_shared_lib_dir()
    lib_path = lib_dir / f"{str(paramset)}-ref.so"
    lib = ffi.dlopen(str(lib_path.absolute()))

    c_pk = ffi.new("uint8_t[]", pk)
    c_m = ffi.new("uint8_t[]", msg)
    c_sig = ffi.new("uint8_t[]", sig)
    c_ctx = ffi.new("uint8_t[]", ctx)

    func = getattr(lib, fname)
    ret = func(c_sig, len(sig), c_m, len(msg), c_ctx, len(ctx), c_pk)

    return ret == 0


# --------------------------- Vectors -------------------------------------------------


def _load_vectors(paramset: Paramset) -> list[MldsaVectors]:
    """Loads vectors for a given parameter set.

    Args:
        paramset: The parameter set to load vectors of.

    Returns:
        A dictionary of vectors, indexed by the name of their source.
    """
    vectors_dir = importlib.resources.files("crypto_condor") / "vectors/_mldsa"
    vectors = list()

    sources_file = vectors_dir / "mldsa.json"
    with sources_file.open("r") as file:
        sources = json.load(file)

    for filename in sources.get(str(paramset)):
        vectors_file = vectors_dir / "pb2" / filename
        _vec = MldsaVectors()
        logger.debug("Loading ML-DSA vectors from %s", str(filename))
        try:
            _vec.ParseFromString(vectors_file.read_bytes())
        except Exception:
            logger.error("Failed to load ML-DSA vectors from %s", str(filename))
            logger.debug("Exception caught while loading vectors", exc_info=True)
        vectors.append(_vec)

    return vectors


# --------------------------- Protocols -----------------------------------------------


class Sign(Protocol):
    """Represents an ML-DSA signing function."""

    def __call__(self, sk: bytes, msg: bytes, ctx: bytes) -> bytes:
        """Signs a message.

        Args:
            sk: The secret key to use.
            msg: The message to sign.
            ctx: The context string. Can be an empty bytestring.

        Returns:
            The signature.
        """
        ...  # pragma: no cover (protocol)


class Verify(Protocol):
    """Represents an ML-DSA signature verification function."""

    def __call__(self, pk: bytes, msg: bytes, sig: bytes, ctx: bytes) -> bool:
        """Verifies an ML-DSA signature.

        Args:
            pk: The public key to use.
            msg: The message that was signed.
            sig: The signature to verify.
            ctx: The context string.

        Returns:
            True if the signature is valid, False otherwise.
        """
        ...  # pragma: no cover (protocol)


# --------------------------- Dataclasses----------------------------------------------


@attrs.define
class SignData:
    """Debug data for :func:`test_sign`.

    Args:
        sk: The secret key.
        msg: The message.
        sm: The signed message.
        ctx: The context string.
        ret_sm: The signed message returned by the implementation.
    """

    sk: bytes
    msg: bytes
    ctx: bytes
    sig: bytes
    ret_sig: bytes | None = None

    def __str__(self) -> str:
        """Returns a string representation."""
        return f"""sk = {self.sk.hex()}
msg = {self.msg.hex() if self.msg else "<empty>"}
ctx = {self.ctx.hex() if self.ctx else "<empty>"}
sig = {self.ctx.hex()}
ret_sig = {self.ret_sig.hex() if self.ret_sig is not None else "<none>"}
"""


@attrs.define
class VerifyData:
    """Debug data for :func:`test_verify`.

    Args:
        pk: The public key.
        sm: The signed message.
        ctx: The context string.
    """

    pk: bytes
    msg: bytes
    sig: bytes
    ctx: bytes

    def __str__(self) -> str:
        """Returns a string representation."""
        return f"""pk = {self.pk.hex()}
msg = {self.msg.hex() if self.msg else "<empty>"}
sig = {self.sig.hex()}
ctx = {self.ctx.hex() if self.ctx is not None else "<empty>"}
"""


# --------------------------- Test functions ------------------------------------------


def test_sign(sign: Sign, paramset: Paramset) -> ResultsDict:
    """Tests a function that signs with ML-DSA.

    Signs messages with the given function. As by default ML-DSA uses a "hedged",
    pseudorandom procedure, the signature cannot be directly compared with the one
    included in the test vector. Instead, crypto-condor checks that the signature has
    the correct length and then verifies it is valid for the test vector public key and
    message using the reference implementation.

    Args:
        sign: The function to test.
        paramset: The parameter set to test.

    Returns:
        A dictionary of results. It is empty if the internal decapsulation failed to
        run, or the implementation raised NotImplementedError.
    """
    param_vectors = _load_vectors(paramset)
    rd = ResultsDict()

    test: MldsaTest
    for vectors in param_vectors:
        results = Results.new("Test ML-DSA signing", ["paramset"])
        results.add_notes(vectors.notes)

        for test in track(
            vectors.tests, rf"\[{paramset}]\[{vectors.source}] Testing signing"
        ):
            info = TestInfo.new_from_test(test, vectors.compliance)
            data = SignData(test.sk, test.msg, test.sig, test.ctx)

            try:
                ret_sig = sign(test.sk, test.msg, test.ctx)
            except NotImplementedError:
                logger.warning("%s Sign not implemented, skipped", str(paramset))
                return rd
            except Exception as error:
                logger.debug("Caught exception", exc_info=True)
                info.fail(f"Exception raised: {str(error)}", data)
                results.add(info)
                continue

            data.ret_sig = ret_sig

            # Check that sm is the correct length.
            if len(ret_sig) != paramset.sig_size:
                info.fail(
                    f"Wrong signature size returned (got {len(ret_sig)},"
                    f" expected {paramset.sig_size})",
                    data,
                )
                results.add(info)
                continue

            # Verify the signature.
            try:
                is_valid_sig = _verify(paramset, test.pk, test.msg, ret_sig, test.ctx)
            except Exception as error:
                logger.debug(
                    "Caught exception while verifying signature", exc_info=True
                )
                info.fail(
                    f"Exception raised, failed to verify signature: {str(error)}", data
                )
                results.add(info)
                continue

            match (is_valid_sig, test.type):
                case (True, TestType.VALID):
                    info.ok(data)
                case (False, TestType.VALID):
                    info.fail("Signatures do not match", data)
                case _:
                    # We currently don't have other type of tests for sign.
                    pass
            results.add(info)

        rd.add(results, ["paramset"])

    return rd


def test_verify(verify: Verify, paramset: Paramset) -> ResultsDict:
    """Tests a function that verified ML-DSA signatures.

    Verifies signatures with the given function. The test passes if valid signatures are
    accepted.

    Args:
        verify: The function to test.
        paramset: The parameter set to test.

    Returns:
        A dictionary of results. It is empty if the internal decapsulation failed to
        run, or the implementation raised NotImplementedError.
    """
    param_vectors = _load_vectors(paramset)
    rd = ResultsDict()

    test: MldsaTest
    for vectors in param_vectors:
        results = Results.new("Test ML-DSA signature verification", ["paramset"])
        results.add_notes(vectors.notes)

        for test in track(
            vectors.tests,
            rf"\[{paramset}]\[{vectors.source}] Testing signature verification",
        ):
            info = TestInfo.new_from_test(test, vectors.compliance)
            data = VerifyData(test.pk, test.msg, test.sig, test.ctx)

            try:
                ret_valid = verify(test.pk, test.msg, test.sig, test.ctx)
            except NotImplementedError:
                logger.warning("%s Verify not implemented, skipped", str(paramset))
                return rd
            except Exception as error:
                logger.debug("Caught exception", exc_info=True)
                info.fail(f"Exception raised: {str(error)}", data)
                results.add(info)
                continue

            match (ret_valid, test.type):
                case (True, TestType.VALID):
                    info.ok(data)
                case (False, TestType.VALID):
                    info.fail("Valid signature rejected", data)
                case _:
                    # we currently don't have other type of tests for encaps
                    pass
            results.add(info)

        rd.add(results, ["paramset"])

    return rd


def test_output_sign(output: Path, paramset: Paramset) -> ResultsDict:
    r"""Tests a file of ML-DSA signatures.

    Args:
        output: A path to the output file.
        paramset: The parameter set of the output.

    Returns:
        A dictionary of results.

    Format:
        - One line per hashing operation, separated by newlines ``\n``.
        - Lines starting with ``#`` are considered comments and ignored.
        - Values are written in hexadecimal.
        - Values are separated by forward slashes ``/``.
        - The order of the values is:

        .. code::

            pk/msg/sig/ctx

        - Where:
            - ``pk`` is the public key.
            - ``msg`` is the message.
            - ``sig`` is the signature.
            - ``ctx`` is the context string.
    """
    if not output.is_file():
        raise FileNotFoundError("No output file '%s' found" % str(output))
    with output.open("r") as file:
        lines = file.readlines()

    results = Results.new("Tests ML-DSA signatures", ["output", "paramset"])
    for index, line in enumerate(lines, 1):
        if line.startswith("#"):
            continue
        line = line.strip()
        match line.split("/"):
            case [_pk, _msg, _sig, _ctx]:
                pk, msg, sig, ctx = map(bytes.fromhex, (_pk, _msg, _sig, _ctx))
            case _:
                logger.error("Failed to parse line %d (expected 4 values)" % index)
                continue

        info = TestInfo.new(index, TestType.VALID, ["UserInput"])
        data = VerifyData(pk, msg, sig, ctx)
        try:
            is_valid_sm = _verify(paramset, pk, msg, sig, ctx)
        except Exception:
            logger.debug("Failed to verify signature", exc_info=True)
            info.fail("Error verifying the signature", data)
            results.add(info)
            continue

        if is_valid_sm:
            info.ok(data)
        else:
            info.fail("Signature is invalid", data)
        results.add(info)

    rd = ResultsDict()
    rd.add(results, ["output", "paramset"])
    return rd


# --------------------------- Runners -------------------------------------------------


def run_python_wrapper(
    wrapper: Path, compliance: bool, resilience: bool
) -> ResultsDict:
    """Runs a ML-DSA Python wrapper.

    Args:
        wrapper: A path to the wrapper to run. Must be a Python program.
        compliance: Whether to use compliance test vectors.
        resilience: Whether to use resilience test vectors.

    Returns:
        A dictionary of results.
    """
    logger.info("Running Python ML-DSA wrapper: %s", str(wrapper.name))
    sys.path.insert(0, str(wrapper.parent.absolute()))
    already_imported = wrapper.stem in sys.modules.keys()
    try:
        mldsa_wrapper = importlib.import_module(wrapper.stem)
    except ModuleNotFoundError as error:
        logger.error("Can't import wrapper: %s", str(error))
        raise
    if already_imported:
        logger.debug("Reloading ML-DSA wrapper: %s", wrapper.stem)
        mldsa_wrapper = importlib.reload(mldsa_wrapper)

    rd = ResultsDict()
    for symbol in dir(mldsa_wrapper):
        match symbol.split("_"):
            case ["CC", "MLDSA", _pset, ("sign" | "verify") as op]:
                logger.info("Found CC_MLKEM function %s", symbol)
                try:
                    paramset = Paramset(f"ML-DSA-{_pset}")
                except ValueError:
                    logger.error("Unknown parameter set ML-DSA-%s for ML-DSA", _pset)
                    continue
                if op == "sign":
                    rd |= test_sign(getattr(mldsa_wrapper, symbol), paramset)
                else:
                    rd |= test_verify(getattr(mldsa_wrapper, symbol), paramset)
            case ["CC", "MLDSA", *_]:
                logger.warning("Ignored unknown CC_MLDSA function %s", symbol)
            case _:
                pass

    return rd


# --------------------------- Harness -------------------------------------------------


def _test_harness_sign(
    ffi: cffi.FFI, lib, function: str, paramset: Paramset
) -> ResultsDict:
    logger.info("Testing harness function %s", function)

    ffi.cdef(
        f"""void {function}(uint8_t *sig, size_t siglen,
                         const uint8_t *msg, size_t msglen,
                         const uint8_t *ctx, size_t ctxlen,
                         const uint8_t *sk, size_t sklen);"""
    )
    sign = getattr(lib, function)

    # Object sizes are fixed in ML-DSA.
    c_sig = ffi.new(f"uint8_t[{paramset.sig_size}]")

    def _sign(sk: bytes, msg: bytes, ctx: bytes) -> bytes:
        c_sk = ffi.new("uint8_t[]", sk)
        c_msg = ffi.new("uint8_t[]", msg)
        c_ctx = ffi.new("uint8_t[]", ctx)
        sign(
            c_sig,
            paramset.sig_size,
            c_msg,
            len(msg),
            c_ctx,
            len(ctx),
            c_sk,
            paramset.sk_size,
        )
        return bytes(c_sig)

    return test_sign(_sign, paramset)


def _test_harness_verify(
    ffi: cffi.FFI, lib, function: str, paramset: Paramset
) -> ResultsDict:
    logger.info("Testing harness function %s", function)

    ffi.cdef(
        f"""int {function}(const uint8_t *sig, size_t siglen,
                          const uint8_t *msg, size_t msglen,
                          const uint8_t *ctx, size_t ctxlen,
                          const uint8_t *pk, size_t pklen);"""
    )
    verify = getattr(lib, function)

    def _verify(pk: bytes, msg: bytes, sig: bytes, ctx: bytes) -> bool:
        c_pk = ffi.new("uint8_t[]", pk)
        c_msg = ffi.new("uint8_t[]", msg)
        c_sig = ffi.new("uint8_t[]", sig)
        c_ctx = ffi.new("uint8_t[]", ctx)

        r = verify(c_sig, len(sig), c_msg, len(msg), c_ctx, len(ctx), c_pk, len(pk))
        if r == 0:
            return True
        elif r == -1:
            return False
        else:
            raise ValueError(f"Error: verify returned {r} (expected 0 or -1)")

    return test_verify(_verify, paramset)


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
            A list of CC_MLDSA functions to test.
        compliance:
            Whether to use compliance test vectors.
        resilience:
            Whether to use resilience test vectors.
    """
    logger.info("Found harness functions %s", ", ".join(functions))

    rd = ResultsDict()

    for function in functions:
        match function.split("_"):
            case ["CC", "MLDSA", pset, ("sign" | "verify") as op]:
                try:
                    paramset = Paramset(f"ML-DSA-{pset}")
                except ValueError:
                    logger.error(
                        "Unknown param set %s, skipped function %s", pset, function
                    )
                    continue
                if op == "sign":
                    rd |= _test_harness_sign(ffi, lib, function, paramset)
                else:
                    rd |= _test_harness_verify(ffi, lib, function, paramset)
            case _:
                logger.warning("Ignored unknown CC_MLDSA function %s", function)
    return rd


if __name__ == "__main__":
    _ = _get_shared_lib_dir()
