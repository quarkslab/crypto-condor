"""Module for testing ML-DSA implementations."""

import hashlib
import importlib
import json
import logging
import shutil
import subprocess
import sys
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
        KeyGen.__name__,
        Sign.__name__,
        Verify.__name__,
        # Test functions
        test_keygen.__name__,
        test_sign.__name__,
        test_sign_deterministic.__name__,
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


# Hash algorithm OIDs for prehash prefix (DER-encoded: 0x06 || 0x09 || 9 bytes OID).
# https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration#Hash
_HASHALGS_PREFIX = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02]
HASH_ALGORITHMS: dict[str, bytes] = {
    "SHA2-224": bytes(_HASHALGS_PREFIX + [0x04]),
    "SHA2-256": bytes(_HASHALGS_PREFIX + [0x01]),
    "SHA2-384": bytes(_HASHALGS_PREFIX + [0x02]),
    "SHA2-512": bytes(_HASHALGS_PREFIX + [0x03]),
    "SHA2-512/224": bytes(_HASHALGS_PREFIX + [0x05]),
    "SHA2-512/256": bytes(_HASHALGS_PREFIX + [0x06]),
    "SHA3-224": bytes(_HASHALGS_PREFIX + [0x07]),
    "SHA3-256": bytes(_HASHALGS_PREFIX + [0x08]),
    "SHA3-384": bytes(_HASHALGS_PREFIX + [0x09]),
    "SHA3-512": bytes(_HASHALGS_PREFIX + [0x0A]),
    "SHAKE-128": bytes(_HASHALGS_PREFIX + [0x0B]),
    "SHAKE-256": bytes(_HASHALGS_PREFIX + [0x0C]),
}


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
    match sys.platform:
        case "linux":
            libs = {
                "libpqcrystals_dilithium2_ref.so": "ML-DSA-44-ref.so",
                "libpqcrystals_dilithium3_ref.so": "ML-DSA-65-ref.so",
                "libpqcrystals_dilithium5_ref.so": "ML-DSA-87-ref.so",
            }
        case "darwin":
            libs = {
                "libpqcrystals_dilithium2_ref.dylib": "ML-DSA-44-ref.dylib",
                "libpqcrystals_dilithium3_ref.dylib": "ML-DSA-65-ref.dylib",
                "libpqcrystals_dilithium5_ref.dylib": "ML-DSA-87-ref.dylib",
            }
        case _:
            raise ValueError(
                f"Unsupported platform {sys.platform}, can't get appdata directory"
            )
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
        if not (rsc / "dilithium/ref").is_dir():
            try:
                subprocess.run(
                    ["make", "all"],
                    cwd=str(rsc),
                    check=True,
                    capture_output=True,
                    timeout=30.0,
                )
            except Exception:
                logger.exception("Failed to patch ML-DSA Makefile for CC usage")
                raise
        try:
            subprocess.run(
                ["make", "shared"],
                cwd=str(rsc / "dilithium/ref"),
                check=True,
                capture_output=True,
                timeout=30.0,
            )
        except subprocess.CalledProcessError:
            logger.exception("Failed to compile ML-DSA implementation")
            raise
        for lib, dst in libs.items():
            src = str(rsc / "dilithium/ref" / lib)
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
    match sys.platform:
        case "linux":
            lib_path = lib_dir / f"{str(paramset)}-ref.so"
        case "darwin":
            lib_path = lib_dir / f"{str(paramset)}-ref.dylib"
        case _:
            raise ValueError(
                f"Unsupported platform {sys.platform}, can't get appdata directory"
            )
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
    match sys.platform:
        case "linux":
            lib_path = lib_dir / f"{str(paramset)}-ref.so"
        case "darwin":
            lib_path = lib_dir / f"{str(paramset)}-ref.dylib"
        case _:
            raise ValueError(
                f"Unsupported platform {sys.platform}, can't get appdata directory"
            )
    lib = ffi.dlopen(str(lib_path.absolute()))

    c_sk = ffi.new("uint8_t[]", sk)
    c_msg = ffi.new("uint8_t[]", msg)
    c_ctx = ffi.new("uint8_t[]", ctx)

    c_sig = ffi.new(f"uint8_t[{paramset.sig_size}]")
    c_siglen = ffi.new("uint8_t *")

    func = getattr(lib, fname)
    func(c_sig, c_siglen, c_msg, len(msg), c_ctx, len(ctx), c_sk)

    return bytes(c_sig)


def _sign_deterministic(paramset: Paramset, sk: bytes, msg: bytes, ctx: bytes) -> bytes:
    """Signs deterministically using the internal implementation.

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
    fname = f"pqcrystals_dilithium{paramset.dilithium}_ref_signature_internal"
    ffi = cffi.FFI()
    ffi.cdef(
        f"""
        int {fname}(uint8_t *sig, size_t *siglen,
                    const uint8_t *m, size_t mlen,
                    const uint8_t *pre, size_t prelen,
                    const uint8_t rnd[32],
                    const uint8_t *sk);
        """
    )

    lib_dir = SHARED_LIB_DIR or _get_shared_lib_dir()
    match sys.platform:
        case "linux":
            lib_path = lib_dir / f"{str(paramset)}-ref.so"
        case "darwin":
            lib_path = lib_dir / f"{str(paramset)}-ref.dylib"
        case _:
            raise ValueError(
                f"Unsupported platform {sys.platform}, can't get appdata directory"
            )
    lib = ffi.dlopen(str(lib_path.absolute()))

    # Construct prefix: pre = (0, ctxlen, ctx)
    pre = bytes([0, len(ctx)]) + ctx

    c_sk = ffi.new("uint8_t[]", sk)
    c_msg = ffi.new("uint8_t[]", msg)
    c_pre = ffi.new("uint8_t[]", pre)
    c_rnd = ffi.new("uint8_t[32]", b"\x00" * 32)

    c_sig = ffi.new(f"uint8_t[{paramset.sig_size}]")
    c_siglen = ffi.new("size_t *")

    func = getattr(lib, fname)
    func(c_sig, c_siglen, c_msg, len(msg), c_pre, len(pre), c_rnd, c_sk)

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
    match sys.platform:
        case "linux":
            lib_path = lib_dir / f"{str(paramset)}-ref.so"
        case "darwin":
            lib_path = lib_dir / f"{str(paramset)}-ref.dylib"
        case _:
            raise ValueError(
                f"Unsupported platform {sys.platform}, can't get appdata directory"
            )
    lib = ffi.dlopen(str(lib_path.absolute()))

    c_pk = ffi.new("uint8_t[]", pk)
    c_m = ffi.new("uint8_t[]", msg)
    c_sig = ffi.new("uint8_t[]", sig)
    c_ctx = ffi.new("uint8_t[]", ctx)

    func = getattr(lib, fname)
    ret = func(c_sig, len(sig), c_m, len(msg), c_ctx, len(ctx), c_pk)

    return ret == 0


def _hash_message(ph: str, msg: bytes) -> bytes:
    """Hashes a message using the specified hash algorithm.

    Args:
        ph: The hash algorithm name (e.g. "SHA2-512", "SHAKE-256").
        msg: The message to hash.

    Returns:
        The hash digest.
    """
    if ph.startswith("SHAKE-128"):
        return hashlib.shake_128(msg).digest(32)
    elif ph.startswith("SHAKE-256"):
        return hashlib.shake_256(msg).digest(64)
    else:
        # Map ACVP hash name to hashlib name
        hash_name = ph.replace("SHA2-", "sha")
        hash_name = hash_name.replace("SHA3-", "sha3_")
        hash_name = hash_name.replace("-", "_")
        hash_name = hash_name.replace("/", "_").lower()
        return hashlib.new(hash_name, msg).digest()


def _build_prehash_prefix(ctx: bytes, ph: str) -> bytes:
    """Builds the prehash prefix for ML-DSA.

    The prefix is: 0x01 || ctxlen || ctx || OID(hash)
    See FIPS 204, Algo 4, line 23 (HashML-DSA.Sign)

    Args:
        ctx: The context string.
        ph: The hash algorithm name.

    Returns:
        The prehash prefix bytes.
    """
    oid = HASH_ALGORITHMS.get(ph)
    if oid is None:
        raise ValueError(f"Unknown hash algorithm: {ph}")
    return bytes([1, len(ctx)]) + ctx + oid


def _verify_prehash(
    paramset: Paramset, pk: bytes, msg: bytes, sig: bytes, ctx: bytes, ph: str
) -> bool:
    """Verifies a prehash signature using the internal implementation.

    Args:
        paramset: The parameter set to use.
        pk: The public key.
        msg: The message that was signed.
        sig: The signature to verify.
        ctx: The context string.
        ph: The hash algorithm name.

    Returns:
        True if the signature is valid, False otherwise.
    """
    h = _hash_message(ph, msg)
    pre = _build_prehash_prefix(ctx, ph)

    fname = f"pqcrystals_dilithium{paramset.dilithium}_ref_verify_internal"
    ffi = cffi.FFI()
    ffi.cdef(
        f"""
        int {fname}(const uint8_t *sig, size_t siglen,
                     const uint8_t *m, size_t mlen,
                     const uint8_t *pre, size_t prelen,
                     const uint8_t *pk);
        """
    )

    lib_dir = SHARED_LIB_DIR or _get_shared_lib_dir()
    match sys.platform:
        case "linux":
            lib_path = lib_dir / f"{str(paramset)}-ref.so"
        case "darwin":
            lib_path = lib_dir / f"{str(paramset)}-ref.dylib"
        case _:
            raise ValueError(
                f"Unsupported platform {sys.platform}, can't get appdata directory"
            )
    lib = ffi.dlopen(str(lib_path.absolute()))

    c_pk = ffi.new("uint8_t[]", pk)
    c_h = ffi.new("uint8_t[]", h)
    c_sig = ffi.new("uint8_t[]", sig)
    c_pre = ffi.new("uint8_t[]", pre)

    func = getattr(lib, fname)
    ret = func(c_sig, len(sig), c_h, len(h), c_pre, len(pre), c_pk)

    return ret == 0


def _sign_prehash(
    paramset: Paramset, sk: bytes, msg: bytes, ctx: bytes, ph: str
) -> bytes:
    """Signs deterministically in prehash mode using the internal implementation.

    Args:
        paramset: The parameter set to use.
        sk: The secret key.
        msg: The message to sign.
        ctx: The context string. Can be an empty bytestring.
        ph: The hash algorithm name.

    Returns:
        The signature.
    """
    h = _hash_message(ph, msg)
    pre = _build_prehash_prefix(ctx, ph)

    fname = f"pqcrystals_dilithium{paramset.dilithium}_ref_signature_internal"
    ffi = cffi.FFI()
    ffi.cdef(
        f"""
        int {fname}(uint8_t *sig, size_t *siglen,
                    const uint8_t *m, size_t mlen,
                    const uint8_t *pre, size_t prelen,
                    const uint8_t rnd[32],
                    const uint8_t *sk);
        """
    )

    lib_dir = SHARED_LIB_DIR or _get_shared_lib_dir()
    match sys.platform:
        case "linux":
            lib_path = lib_dir / f"{str(paramset)}-ref.so"
        case "darwin":
            lib_path = lib_dir / f"{str(paramset)}-ref.dylib"
        case _:
            raise ValueError(
                f"Unsupported platform {sys.platform}, can't get appdata directory"
            )
    lib = ffi.dlopen(str(lib_path.absolute()))

    c_sk = ffi.new("uint8_t[]", sk)
    c_h = ffi.new("uint8_t[]", h)
    c_pre = ffi.new("uint8_t[]", pre)
    c_rnd = ffi.new("uint8_t[32]", b"\x00" * 32)

    c_sig = ffi.new(f"uint8_t[{paramset.sig_size}]")
    c_siglen = ffi.new("size_t *")

    func = getattr(lib, fname)
    func(c_sig, c_siglen, c_h, len(h), c_pre, len(pre), c_rnd, c_sk)

    return bytes(c_sig)


# --------------------------- Vectors -------------------------------------------------


def _load_vectors(
    paramset: Paramset,
    category: str = "",
    prehash: bool = False,
    compliance: bool = True,
    resilience: bool = False,
) -> list[MldsaVectors]:
    """Loads vectors for a given parameter set.

    Args:
        paramset:
            The parameter set to load vectors of.
        category:
            Optional category filter. One of "keyGen", "sigGen", "sigVer".
            If empty, loads all vectors.
        prehash:
            If True, load prehash variant vectors. If False, load pure variant.
        compliance:
            If True, load compliance test vectors.
        resilience:
            If True, load resilience test vectors.

    Returns:
        A list of vectors.
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
            logger.exception("Failed to load ML-DSA vectors from %s", str(filename))

        if category:
            if _vec.category != category:
                continue
        else:
            # When no category filter, skip category-specific vectors
            # (e.g., FIPS 204 keyGen/sigGen/sigVer) to avoid duplicates
            if _vec.category:
                continue

        # Filter by prehash flag
        if _vec.prehash != prehash:
            continue

        # Filter by compliance/resilience
        if _vec.compliance and compliance:
            vectors.append(_vec)
        if not _vec.compliance and resilience:
            vectors.append(_vec)

    return vectors


# --------------------------- Protocols -----------------------------------------------


class Sign(Protocol):
    """Represents an ML-DSA signing function."""

    def __call__(
        self, sk: bytes, msg: bytes, ctx: bytes, ph: str = ""
    ) -> tuple[bool, bytes]:
        """Signs a message.

        Args:
            sk: The secret key to use.
            msg: The message to sign.
            ctx: The context string. Can be an empty bytestring.
            ph: For the prehash variant, the name of the hash function (e.g.
                ``"SHA2-512"``). For the pure variant, it is an empty string and
                should be ignored.

        Returns:
            A tuple (success, signature). success is True if signing succeeded,
            False if the implementation rejected the input (e.g. invalid key length).
        """
        ...  # pragma: no cover (protocol)


class Verify(Protocol):
    """Represents an ML-DSA signature verification function."""

    def __call__(
        self, pk: bytes, msg: bytes, sig: bytes, ctx: bytes, ph: str = ""
    ) -> bool:
        """Verifies an ML-DSA signature.

        Args:
            pk: The public key to use.
            msg: The message that was signed.
            sig: The signature to verify.
            ctx: The context string.
            ph: For the prehash variant, the name of the hash function (e.g.
                ``"SHA2-512"``). For the pure variant, it is an empty string and
                should be ignored.

        Returns:
            True if the signature is valid, False otherwise.
        """
        ...  # pragma: no cover (protocol)


class KeyGen(Protocol):
    """Represents an ML-DSA key generation function."""

    def __call__(self, seed: bytes) -> tuple[bytes, bytes]:
        """Generates an ML-DSA key pair from a seed.

        Args:
            seed: The seed for key generation (32 bytes).

        Returns:
            A tuple (pk, sk) containing the public and secret key.
        """
        ...  # pragma: no cover (protocol)


# --------------------------- Dataclasses----------------------------------------------


@attrs.define
class SignData:
    """Debug data for :func:`test_sign`.

    Args:
        sk: The secret key.
        msg: The message.
        ctx: The context string.
        ph: The hash function for prehash mode.
        sig: The signature.
        ret_sig: The signature returned by the implementation.
    """

    sk: bytes
    msg: bytes
    ctx: bytes
    sig: bytes
    ph: str | None = None
    ret_sig: bytes | None = None

    @classmethod
    def from_test(cls, test: MldsaTest):
        """Creates a new instance from a test."""
        return cls(test.sk, test.msg, test.ctx, test.sig, test.hashAlg)

    def __str__(self) -> str:
        """Returns a string representation."""
        return f"""sk = {self.sk.hex()}
msg = {self.msg.hex() if self.msg else "<empty>"}
ctx = {self.ctx.hex() if self.ctx else "<empty>"}
sig = {self.sig.hex()}
ph = {self.ph if self.ph is not None else "<none>"}
ret_sig = {self.ret_sig.hex() if self.ret_sig is not None else "<none>"}
"""


@attrs.define
class VerifyData:
    """Debug data for :func:`test_verify`.

    Args:
        pk: The public key.
        msg: The message.
        sig: The signature.
        ctx: The context string.
        ph: The hash function for prehash mode.
        ret_valid_sig: Whether the signature is considered valid by the implementation.
    """

    pk: bytes
    msg: bytes
    sig: bytes
    ctx: bytes
    ph: str | None = None
    ret_valid_sig: bool | None = None

    @classmethod
    def from_test(cls, test: MldsaTest):
        """Creates a new instance from a test."""
        return cls(test.pk, test.msg, test.sig, test.ctx, test.hashAlg)

    def __str__(self) -> str:
        """Returns a string representation."""
        return f"""pk = {self.pk.hex()}
msg = {self.msg.hex() if self.msg else "<empty>"}
sig = {self.sig.hex()}
ctx = {self.ctx.hex() if self.ctx is not None else "<empty>"}
ph = {self.ph if self.ph is not None else "<none>"}
ret_valid_sig = {self.ret_valid_sig if self.ret_valid_sig is not None else "<none>"}
"""


# --------------------------- Test functions ------------------------------------------


def test_sign(
    sign: Sign,
    paramset: Paramset,
    prehash: bool = False,
    compliance: bool = True,
    resilience: bool = False,
) -> ResultsDict:
    """Tests a function that signs with ML-DSA.

    Signs messages with the given function. As by default ML-DSA uses a "hedged",
    pseudorandom procedure, the signature cannot be directly compared with the one
    included in the test vector. Instead, crypto-condor checks that the signature has
    the correct length and then verifies it is valid for the test vector public key and
    message using the reference implementation.

    Args:
        sign: The function to test.
        paramset: The parameter set to test.
        prehash: If True, test the prehash variant.
        compliance: If True, use compliance test vectors.
        resilience: If True, use resilience test vectors.

    Returns:
        A dictionary of results. It is empty if the internal decapsulation failed to
        run, or the implementation raised NotImplementedError.
    """
    rd = ResultsDict()

    param_vectors = _load_vectors(paramset, "sigGen", prehash, compliance, resilience)
    if not param_vectors:
        logger.error(
            "no ML-DSA sigGen test vectors for %s (%s version)",
            str(paramset),
            "prehash" if prehash else "pure",
        )
        return rd

    prehash_str = "prehash" if prehash else "pure"

    test: MldsaTest
    for vectors in param_vectors:
        results = Results.new("Test ML-DSA signing", ["paramset", "prehash"])
        results.add_notes(vectors.notes)

        for test in track(
            vectors.tests, rf"\[{paramset}]\[{vectors.source}] "
            rf"Testing {prehash_str} hedged signing"
        ):
            info = TestInfo.new_from_test(test, vectors.compliance)
            data = SignData.from_test(test)

            try:
                (success, ret_sig) = sign(test.sk, test.msg, test.ctx, test.hashAlg)
            except NotImplementedError:
                logger.warning("%s Sign not implemented, skipped", str(paramset))
                return rd
            except Exception as error:
                logger.debug("Caught exception", exc_info=True)
                info.fail(f"Exception raised: {str(error)}", data)
                results.add(info)
                continue

            # Treat failure to sign early
            match (success, test.type):
                case (False, TestType.INVALID):
                    info.ok(data)
                    continue
                case (False, TestType.VALID):
                    info.fail("Failed to generate signature in valid case", data)
                    continue
                case (False, _):
                    raise NotImplementedError(
                        "Unhandled test type for error in signature generation",
                        data,
                    )

            # Now assuming signature generated without error
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
                if prehash:
                    is_valid_sig = _verify_prehash(
                        paramset, test.pk, test.msg, ret_sig, test.ctx, test.hashAlg
                    )
                else:
                    is_valid_sig = _verify(
                        paramset, test.pk, test.msg, ret_sig, test.ctx
                    )
            except Exception as error:
                logger.debug(
                    "Caught exception while verifying signature", exc_info=True
                )
                info.fail(
                    f"Exception raised, failed to verify signature: {str(error)}",
                    data
                )
                results.add(info)
                continue

            match (is_valid_sig, test.type):
                case (True, TestType.VALID):
                    info.ok(data)
                case (False, TestType.VALID):
                    info.fail("Reference refused signature", data)
                case (False, TestType.INVALID):
                    info.ok(data)
                case (True, TestType.INVALID):
                    info.fail("Signature generated in invalid case", data)
                case _:
                    raise ValueError(
                        f"Invalid test result {is_valid_sig} for {test.type} test"
                    )
            results.add(info)

        rd.add(results, ["paramset", "prehash"], extra_values=[vectors.source])

    return rd


def test_verify(
    verify: Verify,
    paramset: Paramset,
    prehash: bool = False,
    compliance: bool = True,
    resilience: bool = False,
) -> ResultsDict:
    """Tests a function that verified ML-DSA signatures.

    Verifies signatures with the given function. The test passes if valid signatures are
    accepted and invalid signatures are rejected.

    Args:
        verify: The function to test.
        paramset: The parameter set to test.
        prehash: If True, test the prehash variant.
        compliance: If True, use compliance test vectors.
        resilience: If True, use resilience test vectors.

    Returns:
        A dictionary of results. It is empty if the verification failed to
        run, or the implementation raised NotImplementedError.
    """
    rd = ResultsDict()

    param_vectors = _load_vectors(paramset, "sigVer", prehash, compliance, resilience)
    if not param_vectors:
        logger.error(
            "No ML-DSA sigVer test vectors for %s (%s version)",
            str(paramset),
            "prehash" if prehash else "pure",
        )
        return rd

    prehash_str = "prehash" if prehash else "pure"

    test: MldsaTest
    for vectors in param_vectors:
        results = Results.new(
            "Test ML-DSA signature verification", ["paramset", "prehash"]
        )
        results.add_notes(vectors.notes)

        for test in track(
            vectors.tests,
            rf"\[{paramset}]\[{vectors.source}] "
            rf"Testing {prehash_str} signature verification",
        ):
            info = TestInfo.new_from_test(test, vectors.compliance)
            data = VerifyData.from_test(test)

            try:
                ret_valid = verify(test.pk, test.msg, test.sig, test.ctx, test.hashAlg)
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
                case (True, TestType.INVALID):
                    info.fail("Invalid signature accepted", data)
                case (False, TestType.INVALID):
                    info.ok(data)
                case _:
                    raise ValueError(
                        f"Invalid test result {ret_valid} for {test.type} test"
                    )
            results.add(info)

        rd.add(results, ["paramset", "prehash"], extra_values=[vectors.source])

    return rd


def test_keygen(
    keygen: KeyGen,
    paramset: Paramset,
    compliance: bool = True,
    resilience: bool = False,
) -> ResultsDict:
    """Tests a function that generates ML-DSA key pairs.

    Calls the keygen function with each test vector's seed and compares the
    resulting public and secret keys with the expected values.

    Args:
        keygen: The function to test.
        paramset: The parameter set to test.
        compliance: If True, use compliance test vectors.
        resilience: If True, use resilience test vectors.

    Returns:
        A dictionary of results.
    """
    rd = ResultsDict()

    param_vectors = _load_vectors(paramset, "keyGen", False, compliance, resilience)
    if not param_vectors:
        logger.error("No ML-DSA keyGen test vectors for %s", str(paramset))
        return rd

    test: MldsaTest
    for vectors in param_vectors:
        results = Results.new("Test ML-DSA key generation", ["paramset"])
        results.add_notes(vectors.notes)

        for test in track(
            vectors.tests, rf"\[{paramset}]\[{vectors.source}] Testing key generation"
        ):
            info = TestInfo.new_from_test(test, vectors.compliance)

            try:
                pk, sk = keygen(test.seed)
            except NotImplementedError:
                logger.warning("%s KeyGen not implemented, skipped", str(paramset))
                return rd
            except Exception as error:
                logger.debug("Caught exception", exc_info=True)
                info.fail(f"Exception raised: {str(error)}")
                results.add(info)
                continue

            if pk != test.pk:
                info.fail("Public key mismatch")
                results.add(info)
                continue

            if sk != test.sk:
                info.fail("Secret key mismatch")
                results.add(info)
                continue

            info.ok()
            results.add(info)

        rd.add(results, ["paramset"], extra_values=[vectors.source])

    return rd


def test_sign_deterministic(
    sign: Sign,
    paramset: Paramset,
    prehash: bool = False,
    compliance: bool = True,
    resilience: bool = False,
) -> ResultsDict:
    """Tests a function that signs with ML-DSA using deterministic signing.

    For deterministic signing (rnd = 00*32), the signature is directly compared
    with the expected value from the test vector.

    Args:
        sign: The function to test.
        paramset: The parameter set to test.
        prehash: If True, test the prehash variant.
        compliance: If True, use compliance test vectors.
        resilience: If True, use resilience test vectors.

    Returns:
        A dictionary of results.
    """
    rd = ResultsDict()

    param_vectors = _load_vectors(paramset, "sigGen", prehash, compliance, resilience)
    if not param_vectors:
        logger.error(
            "No ML-DSA sigGen test vectors for %s (%s version)",
            str(paramset),
            "prehash" if prehash else "pure",
        )
        return rd

    prehash_str = "prehash" if prehash else "pure"

    test: MldsaTest
    for vectors in param_vectors:
        results = Results.new(
            "Test ML-DSA deterministic signing", ["paramset", "prehash"]
        )
        results.add_notes(vectors.notes)

        for test in track(
            vectors.tests,
            rf"\[{paramset}]\[{vectors.source}] "
            rf"Testing {prehash_str} deterministic signing",
        ):
            # Only test deterministic vectors with external message
            if not test.deterministic or test.externalMu:
                continue

            info = TestInfo.new_from_test(test, vectors.compliance)
            data = SignData.from_test(test)

            try:
                (success, ret_sig) = sign(test.sk, test.msg, test.ctx, test.hashAlg)
            except NotImplementedError:
                logger.warning("%s Sign not implemented, skipped", str(paramset))
                return rd
            except Exception as error:
                logger.debug("Caught exception", exc_info=True)
                info.fail(f"Exception raised: {str(error)}", data)
                results.add(info)
                continue

            # Treat failure to sign early
            match (success, test.type):
                case (False, TestType.INVALID):
                    info.ok(data)
                    continue
                case (False, TestType.VALID):
                    info.fail("Failed to generate signature in valid case", data)
                    continue
                case (False, _):
                    raise NotImplementedError(
                        "Unhandled test type for error in signature generation",
                        data,
                    )

            # Now assuming signature generated without error
            data.ret_sig = ret_sig

            if len(ret_sig) != paramset.sig_size:
                info.fail(
                    f"Wrong signature size returned (got {len(ret_sig)},"
                    f" expected {paramset.sig_size})",
                    data,
                )
                results.add(info)
                continue

            if ret_sig != test.sig:
                info.fail(
                    "Deterministic signature mismatch",
                    data,
                )
                results.add(info)
                continue

            info.ok(data)
            results.add(info)

        rd.add(results, ["paramset", "prehash"], extra_values=[vectors.source])

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
            case ["CC", "MLDSA", _pset, "keygen"]:
                logger.info("Found CC_MLDSA function %s", symbol)
                try:
                    paramset = Paramset(f"ML-DSA-{_pset}")
                except ValueError:
                    logger.error("Unknown parameter set ML-DSA-%s for ML-DSA", _pset)
                    continue

                rd |= test_keygen(
                    getattr(mldsa_wrapper, symbol),
                    paramset,
                    compliance,
                    resilience,
                )
            case [
                "CC",
                "MLDSA",
                _pset,
                ("sign" | "verify") as op,
                ("pure" | "prehash") as variant,
            ]:
                logger.info("Found CC_MLDSA function %s", symbol)
                try:
                    paramset = Paramset(f"ML-DSA-{_pset}")
                except ValueError:
                    logger.error("Unknown parameter set ML-DSA-%s for ML-DSA", _pset)
                    continue

                if variant == "pure":
                    prehash = False
                else:
                    prehash = True

                if op == "sign":
                    rd |= test_sign(
                        getattr(mldsa_wrapper, symbol),
                        paramset,
                        prehash,
                        compliance,
                        resilience,
                    )
                else:
                    rd |= test_verify(
                        getattr(mldsa_wrapper, symbol),
                        paramset,
                        prehash,
                        compliance,
                        resilience,
                    )
            case [
                "CC",
                "MLDSA",
                _pset,
                "sign",
                "deterministic",
                ("pure" | "prehash") as variant,
            ]:
                logger.info("Found CC_MLDSA function %s", symbol)
                try:
                    paramset = Paramset(f"ML-DSA-{_pset}")
                except ValueError:
                    logger.error("Unknown parameter set ML-DSA-%s for ML-DSA", _pset)
                    continue

                if variant == "pure":
                    prehash = False
                else:
                    prehash = True

                rd |= test_sign_deterministic(
                    getattr(mldsa_wrapper, symbol),
                    paramset,
                    prehash,
                    compliance,
                    resilience,
                )
            case ["CC", "MLDSA", *_]:
                logger.warning("Ignored unknown CC_MLDSA function %s", symbol)
            case _:
                pass

    return rd


# --------------------------- Harness -------------------------------------------------


def _test_harness_sign(
    ffi: cffi.FFI,
    lib,
    function: str,
    paramset: Paramset,
    prehash: bool = False,
    compliance: bool = True,
    resilience: bool = False,
) -> ResultsDict:
    logger.info("Testing harness function %s", function)

    if prehash:
        ffi.cdef(
            f"""int {function}(uint8_t *sig, size_t siglen,
                             const uint8_t *msg, size_t msglen,
                             const uint8_t *ctx, size_t ctxlen,
                             const uint8_t *sk, size_t sklen,
                             const char *ph, size_t phlen);""",
            override=True,
        )
    else:
        ffi.cdef(
            f"""int {function}(uint8_t *sig, size_t siglen,
                             const uint8_t *msg, size_t msglen,
                             const uint8_t *ctx, size_t ctxlen,
                             const uint8_t *sk, size_t sklen);"""
        )
    sign = getattr(lib, function)

    # Object sizes are fixed in ML-DSA.
    c_sig = ffi.new(f"uint8_t[{paramset.sig_size}]")

    if prehash:

        def _sign(
            sk: bytes, msg: bytes, ctx: bytes, ph: str = ""
        ) -> tuple[bool, bytes]:
            c_sk = ffi.new("uint8_t[]", sk)
            c_msg = ffi.new("uint8_t[]", msg)
            c_ctx = ffi.new("uint8_t[]", ctx)
            c_ph = ffi.new("char[]", ph.encode("utf-8"))
            r = sign(
                c_sig,
                paramset.sig_size,
                c_msg,
                len(msg),
                c_ctx,
                len(ctx),
                c_sk,
                paramset.sk_size,
                c_ph,
                len(ph),
            )

            if r == 0:
                return True, bytes(c_sig)
            elif r == -1:
                return False, bytes(c_sig)
            else:
                raise ValueError(
                    f"Error: sign (prehash) returned {r} (expected 0 or -1)"
                )
    else:

        def _sign(
            sk: bytes, msg: bytes, ctx: bytes, ph: str = ""
        ) -> tuple[bool, bytes]:
            c_sk = ffi.new("uint8_t[]", sk)
            c_msg = ffi.new("uint8_t[]", msg)
            c_ctx = ffi.new("uint8_t[]", ctx)
            r = sign(
                c_sig,
                paramset.sig_size,
                c_msg,
                len(msg),
                c_ctx,
                len(ctx),
                c_sk,
                paramset.sk_size,
            )

            if r == 0:
                return True, bytes(c_sig)
            elif r == -1:
                return False, bytes(c_sig)
            else:
                raise ValueError(f"Error: sign (pure) returned {r} (expected 0 or -1)")

    return test_sign(
        _sign, paramset, prehash=prehash,
        compliance=compliance, resilience=resilience,
    )


def _test_harness_verify(
    ffi: cffi.FFI,
    lib,
    function: str,
    paramset: Paramset,
    prehash: bool = False,
    compliance: bool = True,
    resilience: bool = False,
) -> ResultsDict:
    logger.info("Testing harness function %s", function)

    if prehash:
        ffi.cdef(
            f"""int {function}(const uint8_t *sig, size_t siglen,
                              const uint8_t *msg, size_t msglen,
                              const uint8_t *ctx, size_t ctxlen,
                              const uint8_t *pk, size_t pklen,
                              const char *ph, size_t phlen);""",
            override=True,
        )
    else:
        ffi.cdef(
            f"""int {function}(const uint8_t *sig, size_t siglen,
                              const uint8_t *msg, size_t msglen,
                              const uint8_t *ctx, size_t ctxlen,
                              const uint8_t *pk, size_t pklen);"""
        )
    verify = getattr(lib, function)

    if prehash:

        def _verify(
            pk: bytes, msg: bytes, sig: bytes, ctx: bytes, ph: str = ""
        ) -> bool:
            c_pk = ffi.new("uint8_t[]", pk)
            c_msg = ffi.new("uint8_t[]", msg)
            c_sig = ffi.new("uint8_t[]", sig)
            c_ctx = ffi.new("uint8_t[]", ctx)
            c_ph = ffi.new("char[]", ph.encode("utf-8"))

            r = verify(
                c_sig,
                len(sig),
                c_msg,
                len(msg),
                c_ctx,
                len(ctx),
                c_pk,
                len(pk),
                c_ph,
                len(ph),
            )
            if r == 0:
                return True
            elif r == -1:
                return False
            else:
                raise ValueError(
                    f"Error: verify (prehash) returned {r} (expected 0 or -1)"
                )
    else:

        def _verify(
            pk: bytes,
            msg: bytes,
            sig: bytes,
            ctx: bytes,
            ph: str = "",
        ) -> bool:
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
                raise ValueError(
                    f"Error: verify (pure) returned {r} (expected 0 or -1)"
                )

    return test_verify(
        _verify, paramset, prehash=prehash,
        compliance=compliance, resilience=resilience,
    )


def _test_harness_keygen(
    ffi: cffi.FFI,
    lib,
    function: str,
    paramset: Paramset,
    compliance: bool = True,
    resilience: bool = False,
) -> ResultsDict:
    logger.info("Testing harness function %s", function)

    ffi.cdef(
        f"""void {function}(uint8_t *pk, size_t pklen,
                          uint8_t *sk, size_t sklen,
                          const uint8_t *seed, size_t seedlen);"""
    )
    keygen = getattr(lib, function)

    def _keygen(seed: bytes) -> tuple[bytes, bytes]:
        c_pk = ffi.new(f"uint8_t[{paramset.pk_size}]")
        c_sk = ffi.new(f"uint8_t[{paramset.sk_size}]")
        c_seed = ffi.new("uint8_t[]", seed)
        keygen(c_pk, paramset.pk_size, c_sk, paramset.sk_size, c_seed, len(seed))
        return bytes(c_pk), bytes(c_sk)

    return test_keygen(_keygen, paramset, compliance=compliance, resilience=resilience)


def _test_harness_sign_deterministic(
    ffi: cffi.FFI,
    lib,
    function: str,
    paramset: Paramset,
    prehash: bool = False,
    compliance: bool = True,
    resilience: bool = False,
) -> ResultsDict:
    logger.info("Testing harness function %s", function)

    if prehash:
        ffi.cdef(
            f"""int {function}(uint8_t *sig, size_t siglen,
                              const uint8_t *msg, size_t msglen,
                              const uint8_t *ctx, size_t ctxlen,
                              const uint8_t *sk, size_t sklen,
                              const char *ph, size_t phlen);""",
            override=True,
        )
    else:
        ffi.cdef(
            f"""int {function}(uint8_t *sig, size_t siglen,
                              const uint8_t *msg, size_t msglen,
                              const uint8_t *ctx, size_t ctxlen,
                              const uint8_t *sk, size_t sklen);"""
        )
    sign = getattr(lib, function)

    c_sig = ffi.new(f"uint8_t[{paramset.sig_size}]")

    if prehash:

        def _sign(
            sk: bytes, msg: bytes, ctx: bytes, ph: str = ""
        ) -> tuple[bool, bytes]:
            c_sk = ffi.new("uint8_t[]", sk)
            c_msg = ffi.new("uint8_t[]", msg)
            c_ctx = ffi.new("uint8_t[]", ctx)
            c_ph = ffi.new("char[]", ph.encode("utf-8"))
            r = sign(
                c_sig,
                paramset.sig_size,
                c_msg,
                len(msg),
                c_ctx,
                len(ctx),
                c_sk,
                len(sk),
                c_ph,
                len(ph),
            )

            if r == 0:
                return True, bytes(c_sig)
            elif r == -1:
                return False, bytes(c_sig)
            else:
                raise ValueError(
                    f"Error: sign_deterministic (prehash) returned {r}"
                    " (expected 0 or -1)"
                )
    else:

        def _sign(
            sk: bytes, msg: bytes, ctx: bytes, ph: str = ""
        ) -> tuple[bool, bytes]:
            c_sk = ffi.new("uint8_t[]", sk)
            c_msg = ffi.new("uint8_t[]", msg)
            c_ctx = ffi.new("uint8_t[]", ctx)
            r = sign(
                c_sig,
                paramset.sig_size,
                c_msg,
                len(msg),
                c_ctx,
                len(ctx),
                c_sk,
                len(sk),
            )

            if r == 0:
                return True, bytes(c_sig)
            elif r == -1:
                return False, bytes(c_sig)
            else:
                raise ValueError(
                    f"Error: sign_deterministic (pure) returned {r} (expected 0 or -1)"
                )

    return test_sign_deterministic(
        _sign, paramset, prehash=prehash,
        compliance=compliance, resilience=resilience,
    )


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
            case ["CC", "MLDSA", pset, "keygen"]:
                try:
                    paramset = Paramset(f"ML-DSA-{pset}")
                except ValueError:
                    logger.error(
                        "Unknown param set %s, skipped function %s", pset, function
                    )
                    continue

                rd |= _test_harness_keygen(
                    ffi, lib, function, paramset,
                    compliance, resilience,
                )
            case [
                "CC",
                "MLDSA",
                pset,
                ("sign" | "verify") as op,
                ("pure" | "prehash") as variant,
            ]:
                try:
                    paramset = Paramset(f"ML-DSA-{pset}")
                except ValueError:
                    logger.error(
                        "Unknown param set %s, skipped function %s", pset, function
                    )
                    continue

                if variant == "pure":
                    prehash = False
                else:
                    prehash = True

                if op == "sign":
                    rd |= _test_harness_sign(
                        ffi, lib, function, paramset,
                        prehash, compliance, resilience,
                    )
                else:
                    rd |= _test_harness_verify(
                        ffi, lib, function, paramset,
                        prehash, compliance, resilience,
                    )
            case [
                "CC",
                "MLDSA",
                pset,
                "sign",
                "deterministic",
                ("pure" | "prehash") as variant,
            ]:
                try:
                    paramset = Paramset(f"ML-DSA-{pset}")
                except ValueError:
                    logger.error(
                        "Unknown param set %s, skipped function %s", pset, function
                    )
                    continue

                if variant == "pure":
                    prehash = False
                else:
                    prehash = True

                rd |= _test_harness_sign_deterministic(
                    ffi, lib, function, paramset, prehash, compliance, resilience
                )
            case _:
                logger.warning("Ignored unknown CC_MLDSA function %s", function)
    return rd


if __name__ == "__main__":
    _ = _get_shared_lib_dir()
