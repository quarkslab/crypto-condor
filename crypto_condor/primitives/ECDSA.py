"""Module for testing ECDSA implementations."""

from __future__ import annotations

import importlib
import inspect
import json
import logging
import tempfile
import warnings
from pathlib import Path
from typing import Protocol, TypeAlias

import attrs
import cffi
import strenum
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from rich.progress import track

from crypto_condor.primitives import TestU01
from crypto_condor.primitives.common import (
    Results,
    ResultsDict,
    TestInfo,
    TestType,
    _load_python_harness,
)
from crypto_condor.vectors._ecdsa.ecdsa_pb2 import (
    EcdsaSigGenTest,
    EcdsaSigGenVectors,
    EcdsaSigVerTest,
    EcdsaSigVerVectors,
)
from crypto_condor.vectors.ecdsa import Curve, Hash

logger = logging.getLogger(__name__)


def __dir__():  # pragma: no cover
    """Defines the public API of the module.

    Useful to define the available auto-completions by IDEs.
    """
    return [
        # Type aliases
        "KeyPair",
        # Enums
        KeyEncoding.__name__,
        PubKeyEncoding.__name__,
        Wrapper.__name__,
        # Protocols
        Verify.__name__,
        Sign.__name__,
        Keygen.__name__,
        # Exceptions
        PubKeyImportError.__name__,
        # Test functions
        test_verify.__name__,
        test_sign.__name__,
        test_output_sign.__name__,
        test_sign_verify_invariant.__name__,
        test_key_pair_gen.__name__,
        # Harnesses
        test_wrapper_python.__name__,
        # Imported
        Curve.__name__,
        Hash.__name__,
    ]


# -------------------------------------------------------------------------------------
# Type aliases
# -------------------------------------------------------------------------------------

KeyPair: TypeAlias = int | tuple[int, int, int] | bytes
"""Represents a private ECDSA key.

- If it's a single int, it corresponds to the private value ``d``.
- If it's a tuple of three int, it contains (d, qx, qy), where ``d`` is the private
  value, ``qx`` and ``qy`` are the coordinates of the public point.
- If it's bytes, it is a DER- or PEM-encoded key.
"""

# -------------------------------------------------------------------------------------
# Enums
# -------------------------------------------------------------------------------------


class VectorType(strenum.StrEnum):
    """Defines the different types of test vectors available."""

    # The names are in lowercase to match the keys in the JSON file.
    SIGVER = "sigver"
    """Vectors to test a function that verifies signatures."""
    SIGGEN = "siggen"
    """Vectors to test a function that generates signatures."""


# TODO: document member docstrings.
class KeyEncoding(strenum.StrEnum):
    """Supported key encodings."""

    PEM = "PEM"
    """The PEM encapsulation format, serialized to bytes."""
    DER = "DER"
    """The binary DER format."""
    INT = "INT"
    """The secret value, serialized to bytes."""


# TODO: document member docstrings.
class PubKeyEncoding(strenum.StrEnum):
    """Supported public key encodings."""

    PEM = "PEM"
    """The PEM encapsulation format, serialized to bytes."""
    DER = "DER"
    """The binary DER format."""
    UNCOMPRESSED = "UNCOMPRESSED"
    """The uncompressed coordinates, serialized to bytes."""


class Wrapper(strenum.StrEnum):
    """Supported languages for wrappers."""

    PYTHON = "Python"


# -------------------------------------------------------------------------------------
# Protocols
# -------------------------------------------------------------------------------------


class Verify(Protocol):
    """Represents a function that verifies ECDSA signatures."""

    def __call__(self, pk: bytes, msg: bytes, sig: bytes) -> bool:
        """Verifies an ECDSA signature.

        Args:
            pk:
                The public elliptic curve key. Can be encoded as PEM, DER, or an integer
                in bytes depending on :enum:`PubKeyEncoding`.
            msg:
                The signed message.
            sig:
                The signature to verify.

        Returns:
            True if the signature is valid, False otherwise.
        """
        ...  # pragma: no cover (protocol)


class Sign(Protocol):
    """Represents a function that signs a message with ECDSA."""

    def __call__(self, sk: bytes, msg: bytes) -> bytes:
        """Signs a message with ECDSA.

        Args:
            sk:
                The private elliptic curve key. Can be encoded as PEM, DER, or an
                integer in bytes depending on :enum:`KeyEncoding`.
            msg:
                The message to sign.

        Returns:
            A DER-encoded signature.
        """
        ...  # pragma: no cover (protocol)


class Keygen(Protocol):
    """Represents a function that generates ECDSA key pairs."""

    def __call__(self) -> KeyPair:
        """Generates an ECDSA key pair.

        Returns:
            A :data:`KeyPair`.
        """
        ...  # pragma: no cover (protocol)


# -------------------------------------------------------------------------------------
# Vectors
# -------------------------------------------------------------------------------------


def _load_vectors(
    vector_type: VectorType,
    curve: Curve,
    algo: Hash,
    compliance: bool,
    resilience: bool,
) -> list[EcdsaSigVerVectors] | list[EcdsaSigGenVectors]:
    """Loads vectors for a given parameter set.

    Args:
        vector_type:
            The type of vectors to load.
        curve:
            The elliptic curve of the vectors.
        algo:
            The hash function of the vectors.
        compliance:
            Whether to load compliance test vectors.
        resilience:
            Whether to load resilience test vectors.

    Returns:
        A list of test vectors.
    """
    vectors: list[EcdsaSigVerVectors] | list[EcdsaSigGenVectors] = list()

    if not compliance and not resilience:
        logger.error("No test vectors selected (compliance=False, resilience=False)")
        return vectors

    vectors_dir = importlib.resources.files("crypto_condor") / "vectors/_ecdsa"

    sources_file = vectors_dir / "ecdsa.json"
    with sources_file.open("r") as file:
        sources = json.load(file)

    # There's always the dict of curves for each vector type.
    curves = sources.get(str(vector_type))
    # But the curve may not be supported for e.g. signature verification.
    algos = curves.get(str(curve), None)
    if algos is None:
        logger.error(
            "No test vectors available for %s and curve %s",
            str(vector_type),
            str(curve),
        )
        return vectors

    # This list may not exist, in which case we will return an empty vectors list.
    _vec: EcdsaSigVerVectors | EcdsaSigGenVectors
    for filename in algos.get(str(algo), {}):
        vectors_file = vectors_dir / "pb2" / filename
        if vector_type == VectorType.SIGGEN:
            _vec = EcdsaSigGenVectors()
        else:
            _vec = EcdsaSigVerVectors()
        logger.debug("Loading ECDSA vectors from %s", str(filename))
        try:
            _vec.ParseFromString(vectors_file.read_bytes())
        except Exception:
            logger.exception("Failed to load ECDSA vectors from %s", str(filename))
        if _vec.compliance and compliance:
            vectors.append(_vec)  # type: ignore
        if not _vec.compliance and resilience:
            vectors.append(_vec)  # type: ignore

    # Notify if no vectors have been loaded.
    if not vectors:
        logger.error(
            "No ECDSA %s test vectors available for curve=%s, hash=%s"
            ", compliance=%s, resilience=%s",
            str(vector_type),
            str(curve),
            str(algo),
            compliance,
            resilience,
        )

    return vectors


# -------------------------------------------------------------------------------------
# Exceptions
# -------------------------------------------------------------------------------------


class PubKeyImportError(ValueError):
    """Exception raised when an error occurred while importing a public key."""

    pass


# -------------------------------------------------------------------------------------
# Dataclasses
# -------------------------------------------------------------------------------------


@attrs.define
class SigGenData:
    """Debug data for signature generation tests.

    Args:
        key:
            The key used.
        msg:
            The message signed.
        sig:
            The signature expected for deterministic ECDSA, None otherwise.
        ret_sig:
            The signature returned by the implementation.
    """

    key: bytes
    msg: bytes
    sig: bytes | None = None
    ret_sig: bytes | None = None

    def __str__(self):
        """Returns string representation."""
        s = f"key = {self.key.hex()}\nmsg = {self.msg.hex()}\n"
        if self.sig is not None:
            s += f"expected sig = {self.sig.hex()}\n"
        s += f"returned sig = {self.ret_sig.hex()}\n"
        return s


@attrs.define
class SigVerData:
    """Debug data for :func:`verify_file`.

    Similar to :class:`SigData`, the difference being that some attributes can be None,
    as a parsing error means we can't even get the key used for the operation.

    Args:
        key: The key used.
        msg: The message signed.
        sig: The signature produced or verified.
        ret: Whether the signature was accepted or not.
    """

    key: bytes | None
    msg: bytes | None
    sig: bytes | None
    ret: bool | None = None

    def __str__(self):
        """Returns string representation."""
        return f"""pubkey = {self.key.hex() if self.key is not None else "<none>"}
msg = {self.msg.hex() if self.msg else "<none>"}
sig = {self.sig.hex() if self.sig else "<none>"}
returned value = {self.ret}
"""


@attrs.define
class KeyGenData:
    """Debug data for key generation tests.

    Args:
        d: The private value.
        qx: X-coordinate of the public point.
        qy: Y-coordinate of the public point.
    """

    d: int
    qx: int | None
    qy: int | None

    def __str__(self):
        """Returns string representation."""
        return f"""d = {self.d}
Qx = {self.qx if self.qx is not None else "<none>"}
Qy = {self.qy if self.qy is not None else "<none>"}
"""


# -------------------------------------------------------------------------------------
# Internal functions
# -------------------------------------------------------------------------------------


def _sign(private_key: bytes, hash_function: Hash, message: bytes) -> bytes:
    """Signs a message.

    Args:
        private_key: The DER-encoded private key.
        hash_function: The hash function to use when hashing the message.
        message: The message to sign.

    Returns:
        The signature.

    Raises:
        ValueError: If the private key could not be loaded.
    """
    loaded_key = serialization.load_der_private_key(private_key, None)
    if not isinstance(loaded_key, ec.EllipticCurvePrivateKey):
        raise ValueError("Loaded key is not an elliptic curve private key.")
    signature = loaded_key.sign(message, ec.ECDSA(hash_function.get_hash_instance()))
    return signature


def _verify(
    pubkey_der: bytes,
    hash_function: Hash,
    message: bytes,
    signature: bytes,
    *,
    pre_hashed: bool = False,
) -> bool:
    """Verifies the signature of a message.

    Args:
        pubkey_der: The DER-encoded uncompressed public key.
        hash_function: The hash function used to generate the signature.
        message: The signed message.
        signature: The DER-encoded signature to verify.

    Keyword Args:
        pre_hashed: Whether the message is already hashed.

    Returns:
        True if the signature is valid, False otherwise.

    Raises:
        PubKeyImportError: If an error occurred when loading the public key.
        ValueError: If the hash function is not supported or recognized.
    """
    try:
        key: ec.EllipticCurvePublicKey = serialization.load_der_public_key(pubkey_der)  # type: ignore
    except ValueError as error:
        logger.debug("Error loading public DER key")
        e = PubKeyImportError(f"Couldn't load the public DER key: {str(error)}")
        raise e from error

    try:
        if not pre_hashed:
            key.verify(
                signature,
                message,
                ec.ECDSA(hash_function.get_hash_instance()),
            )
        else:
            key.verify(
                signature,
                message,
                ec.ECDSA(Prehashed(hash_function.get_hash_instance())),
            )
    except InvalidSignature:
        logger.debug("Invalid signature", exc_info=True)
        return False
    except Exception:
        logger.exception("Internal ECDSA verifier error")
        return False

    return True


def _encode_pubkey(encoding: PubKeyEncoding, curve: Curve, key: bytes) -> bytes:
    """Internal function for encoding the public key.

    Args:
        encoding: The target encoding.
        curve: The elliptic curve to use, as the info is not included in the key.
        key: The key to encode, as uncompressed coordinates.

    Returns:
        The public key encoded as an uncompressed point.
    """
    if encoding == PubKeyEncoding.UNCOMPRESSED:
        return key

    pubkey = ec.EllipticCurvePublicKey.from_encoded_point(
        curve.get_curve_instance(), key
    )

    if encoding == PubKeyEncoding.DER:
        return pubkey.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    else:
        return pubkey.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )


def _encode_key(encoding: KeyEncoding, curve: Curve, key: bytes) -> bytes:
    """Internal function for encoding the private key.

    Args:
        encoding: The target encoding.
        curve: The elliptic curve to use, as the info is not included in the key.
        key: The key to encode, as the serialized scalar value.

    Returns:
        The private key encoded as an int.
    """
    if encoding == KeyEncoding.INT:
        return key

    sk = ec.derive_private_key(int.from_bytes(key, "big"), curve.get_curve_instance())

    if encoding == KeyEncoding.DER:
        return sk.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

    return sk.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _load_pem_or_der(key: bytes):
    """Internal function to load a PEM or DER key.

    It guesses which type of key it is by trying to load it as either type.

    Args:
        key: The serialized key to load.

    Returns:
        The corresponding :class:`EllipticCurvePrivateKey`.

    Raises:
        ValueError:
            If the key could not be loaded as either type.
        TypeError:
            If the key is not a private elliptic curve key.
    """
    try:
        pem = serialization.load_pem_private_key(key, None)
        if not isinstance(pem, ec.EllipticCurvePrivateKey):
            raise TypeError("Not an elliptic curve private key")
        return pem
    except TypeError:
        # Re-raise our TypeError.
        raise
    except Exception:
        # Ignore this error since we are guessing the type of key.
        pass
    try:
        der = serialization.load_der_private_key(key, None)
        if not isinstance(pem, ec.EllipticCurvePrivateKey):
            raise TypeError("Not an elliptic curve private key")
        return der
    except TypeError:
        # Re-raise our TypeError.
        raise
    except Exception as error:
        # If the second guess is incorrect too, there's a problem.
        raise ValueError("Failed to load key as PEM or DER") from error


# -------------------------------------------------------------------------------------
# Tests
# -------------------------------------------------------------------------------------


def test_verify(
    verify: Verify,
    curve: Curve,
    hash_function: Hash,
    pubkey_encoding: PubKeyEncoding,
    *,
    pre_hashed: bool = False,
    compliance: bool = True,
    resilience: bool = False,
) -> ResultsDict:
    """Tests a function that verifies ECDSA signatures.

    The ``verify`` function is called to verify messages. The test passes if valid
    signatures are correctly verified, and invalid signatures are rejected.

    The available tests use valid keys and messages, invalid tests only modify the
    signature. Following :protocol:`Verify`, implementations are expected to only return
    True or False, exceptions are treated as errors regardless of test vector and
    counted as failures.

    This function can be used to test implementations of the :rfc:`6979` deterministic
    version of ECDSA.

    Available test vectors depend on the given curve and hash function, see
    `here <https://quarkslab.github.io/crypto-condor/latest/python-api/primitives/ECDSA.html#test-vectors>`_.

    Args:
        verify:
            The function to test.
        curve:
            The elliptic curve to use.
        hash_function:
            The hash function used to generate the signatures.
        pubkey_encoding:
            A public key encoding accepted by the function.

    Keyword Args:
        pre_hashed:
            If True, the messages are hashed before passing them to ``verify``.
        compliance:
            Whether to use compliance test vectors.
        resilience:
            Whether to use resilience test vectors.

    Returns:
        A dictionary of :class:`Results`, one for each test vectors file used. May be
        empty if there are no test vectors for the given curve and hash function.

    Example:
        Let's test ECDSA verification with :mod:`cryptography`.

        >>> from cryptography.exceptions import InvalidSignature
        >>> from cryptography.hazmat.primitives import serialization
        >>> from cryptography.hazmat.primitives.asymmetric import ec

        We also import crypto-condor's ECSDA module to run the tests.

        >>> from crypto_condor.primitives import ECDSA

        We define the parameters we want to test (curve, hash, encoding).

        >>> curve = ECDSA.Curve.P256
        >>> hash_function = ECDSA.Hash.SHA256
        >>> encoding = ECDSA.PubKeyEncoding.DER

        Then wrap the call to the verifier to match the :protocol:`Verify` protocol.

        >>> def my_verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
        ...     key = serialization.load_der_public_key(pk)
        ...     try:
        ...         key.verify(sig, msg, ec.ECDSA(hash_function.get_hash_instance()))
        ...     except InvalidSignature:
        ...         return False
        ...     else:
        ...         return True

        And test this function.

        >>> res = ECDSA.test_verify(my_verify, curve, hash_function, encoding)
        [P-256][SHA-256][NIST CAVP] Test verifying ...

        >>> assert res.check()
    """
    rd = ResultsDict()

    loaded_vectors = _load_vectors(
        VectorType.SIGVER, curve, hash_function, compliance, resilience
    )
    if not loaded_vectors:
        return rd

    test: EcdsaSigVerTest
    for vectors in loaded_vectors:
        results = Results.new(
            "Test ECDSA signature verification",
            ["curve", "hash_function", "pubkey_encoding", "pre_hashed"],
            vectors,
        )
        rd.add(results, extra_values=[vectors.source])

        desc = rf"\[{curve}]\[{hash_function}]\[{vectors.source}] Test verifying"
        for test in track(vectors.tests, desc):  # type: ignore
            # TODO: handle acceptable tests, decide which should be accepted or not.
            if test.type == TestType.ACCEPTABLE:
                continue

            pubkey = _encode_pubkey(pubkey_encoding, curve, test.pubkey)
            if pre_hashed:
                digest = hashes.Hash(hash_function.get_hash_instance())
                digest.update(test.msg)
                msg = digest.finalize()
            else:
                msg = test.msg
            data = SigVerData(pubkey, msg, test.sig)

            info = TestInfo.new_from_test(test, vectors.compliance, data)

            try:
                data.ret = verify(pubkey, msg, test.sig)
            except NotImplementedError:
                logger.error(
                    "ECDSA verify not implemented for curve=%s, hash=%s, skipped test",
                    str(curve),
                    str(hash_function),
                )
                return rd
            except Exception as error:
                logger.debug("Caught exception from ECDSA verify", exc_info=True)
                info.fail(f"Exception raised: {str(error)}")
                results.add(info)
                continue

            match (test.type, data.ret):
                case (TestType.VALID, True):
                    info.ok()
                case (TestType.VALID, False):
                    info.fail("Valid signature rejected")
                case (TestType.INVALID, True):
                    info.fail("Invalid signature accepted")
                case (TestType.INVALID, False):
                    info.ok()
                case (TestType(), _):
                    info.fail(f"Expected True or False, got {type(data.ret)}")
                    data.ret = None
                case _:
                    # TODO: handle acceptable tests, choose those that can pass or not
                    raise ValueError(
                        f"Invalid test result {data.ret} for {test.type} test"
                    )
            results.add(info)

    return rd


def test_sign(
    sign: Sign,
    curve: Curve,
    hash_function: Hash,
    key_encoding: KeyEncoding,
    *,
    pre_hashed: bool = False,
    compliance: bool = True,
    resilience: bool = False,
) -> ResultsDict:
    """Tests a function that signs with ECDSA.

    The ``sign`` function is called to sign messages. Since ECDSA is non-deterministic
    (except when using RFC 6979), |cc| cannot compare the generated signatures with a
    reference value. Instead, it *verifies* the signatures with a reference
    implementation. The test passes if the signature is considered valid.

    Note that this method allows to test the :rfc:`6979` deterministic version of ECDSA,
    as the signatures remain compatible. However, it only tests that the signatures
    produced are valid ECDSA signatures: they may be invalid for RFC 6979. Test vectors
    for deterministic ECDSA will be added.

    Available test vectors depend on the given curve and hash function, see
    `here <https://quarkslab.github.io/crypto-condor/latest/python-api/primitives/ECDSA.html#test-vectors>`_.

    Args:
        sign:
            The function to test.
        curve:
            The elliptic curve to use.
        hash_function:
            The hash function used to generate the signatures.
        key_encoding:
            A private key encoding accepted by the function.

    Keyword Args:
        pre_hashed:
            If True, the messages are hashed before passing them to ``sign``.
        compliance:
            Whether to use compliance test vectors.
        resilience:
            Whether to use resilience test vectors.

    Returns:
        A dictionary of :class:`Results`, one for each test vectors file used. May be
        empty if there are no test vectors for the given curve and hash function.

    Example:
        Let's test crypto-condor's internal signer. First import the ECDSA module.

        >>> from crypto_condor.primitives import ECDSA

        We define the parameters we want to test (curve, hash, encoding).

        >>> curve = ECDSA.Curve.P256
        >>> hash_function = ECDSA.Hash.SHA256
        >>> encoding = ECDSA.KeyEncoding.DER

        Then wrap the function to match the expected signature, defined by
        :protocol:`Sign`.

        >>> def my_sign(private_key: bytes, message: bytes) -> bytes:
        ...     return ECDSA._sign(private_key, hash_function, message)

        And test the function.

        >>> results = ECDSA.test_sign(my_sign, curve, hash_function, encoding)
        [P-256][SHA-256][NIST CAVP] Test signing ...
        >>> assert results.check()
    """
    rd = ResultsDict()

    loaded_vectors = _load_vectors(
        VectorType.SIGGEN, curve, hash_function, compliance, resilience
    )
    if not loaded_vectors:
        return rd

    test: EcdsaSigGenTest
    for vectors in loaded_vectors:
        results = Results.new(
            "Test ECDSA signing",
            ["curve", "hash_function", "key_encoding", "pre_hashed"],
            vectors,
        )
        rd.add(results)

        desc = rf"\[{curve}]\[{hash_function}]\[{vectors.source}] Test signing"
        for test in track(vectors.tests, desc):  # type: ignore
            key = _encode_key(key_encoding, curve, test.d)
            if pre_hashed:
                digest = hashes.Hash(hash_function.get_hash_instance())
                digest.update(test.msg)
                msg = digest.finalize()
            else:
                msg = test.msg
            data = SigGenData(key, msg)

            info = TestInfo.new_from_test(test, vectors.compliance, data)

            try:
                data.ret_sig = sign(key, msg)
            except NotImplementedError:
                logger.error(
                    "ECDSA sign not implemented for curve=%s, hash=%s, skipped test",
                    str(curve),
                    str(hash_function),
                )
                return rd
            except Exception as error:
                logger.debug("Caught exception in ECDSA sign", exc_info=True)
                info.fail(f"Exception raised: {str(error)}")
                results.add(info)
                continue

            # Create private key object and derive the public key to verify the returned
            # signature.
            d = int.from_bytes(test.d, "big")
            sk = ec.derive_private_key(d, curve.get_curve_instance())
            pk = sk.public_key()
            pk_bytes = pk.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            ret_valid = _verify(
                pk_bytes, hash_function, msg, data.ret_sig, pre_hashed=pre_hashed
            )

            match (test.type, ret_valid):
                case (TestType.VALID, True):
                    info.ok()
                case (TestType.VALID, False):
                    info.fail("Signature is invalid")
                case _:
                    # We currently only have NIST vectors, so no invalid or acceptable
                    # tests.
                    raise ValueError(f"Unexpected test type {str(test.type)}")
            results.add(info)

    return rd


def test_sign_verify_invariant(
    sign: Sign,
    verify: Verify,
    curve: Curve,
    hash_function: Hash,
    key_encoding: KeyEncoding,
    pubkey_encoding: PubKeyEncoding,
    *,
    prehash: bool = False,
) -> ResultsDict:
    """Tests signing and verifying.

    A signature generated by an implementation should be valid for its own verifier. To
    test this, available signature generation test vectors are used. The :attr:`sign`
    function is called to compute the signature, then the :attr:`verify` function is
    called to verify this signature. The test passes if the signature is considered
    valid.

    Note that this only verifies that the signer and verifier agree: for example, a
    verifier that returns True no matter the input will pass this test. Consider also
    testing both functions with :func:`test_sign` and :func:`test_verify`.

    Available test vectors depend on the given curve and hash function, see
    `here <https://quarkslab.github.io/crypto-condor/latest/python-api/primitives/ECDSA.html#test-vectors>`_.

    Args:
        sign:
            The signing function to test.
        verify:
            The verifying function to test.
        curve:
            The elliptic curve to use.
        hash_function:
            This argument is used to select the test vectors to use. If the ``prehash``
            argument is True, it also selects the hash function used to hash the
            messages before passing them to both functions.
        key_encoding:
            The private key encoding used by the signing function.
        pubkey_encoding:
            The public key encoding used by the verifying function.

    Keyword Args:
        prehash:
            If True, messages are hashed before passing them to ``sign`` and ``verify``,
            otherwise messages are given as-is.

    Returns:
        A dictionary of results, containing one instance of :class:`Results` per test
        vectors file used.

    Example:
        Let's test crypto-condor's internal functions. First import the ECDSA module.

        >>> from crypto_condor.primitives import ECDSA

        Define the test parameters.

        >>> curve = ECDSA.Curve.P256
        >>> hash_function = ECDSA.Hash.SHA256
        >>> key_encoding = ECDSA.KeyEncoding.DER
        >>> pubkey_encoding = ECDSA.PubKeyEncoding.DER

        Wrap both functions to match the corresponding protocols (:protocol:`Verify` and
        :protocol:`Sign`).

        >>> def my_verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
        ...     return ECDSA._verify(pk, hash_function, msg, sig)
        >>> def my_sign(sk: bytes, msg: bytes) -> bytes:
        ...     return ECDSA._sign(sk, hash_function, msg)

        Then test both functions.

        >>> results = ECDSA.test_sign_verify_invariant(
        ...     my_sign, my_verify, curve, hash_function, key_encoding, pubkey_encoding
        ... )
        [P-256][SHA-256][NIST CAVP] Test sign-verify ...
        >>> assert results.check()
    """  # noqa: E501
    rd = ResultsDict()

    # We can use all test vectors available, hence compliance=True and resilience=True.
    # We only have to watch out for invalid test vectors, so we check the type below.
    loaded_vectors = _load_vectors(VectorType.SIGGEN, curve, hash_function, True, True)
    if not loaded_vectors:
        return rd

    test: EcdsaSigGenTest
    for vectors in loaded_vectors:
        results = Results.new(
            "Test sign-verify invariant",
            ["curve", "hash_function", "key_encoding", "pubkey_encoding"],
            vectors,
        )
        rd.add(results)

        desc = rf"\[{curve}]\[{hash_function}]\[{vectors.source}] Test sign-verify"
        for test in track(vectors.tests, desc):  # type: ignore
            # NOTE: for now, skipping all invalid test vectors. In practice we could use
            # those that modify the resulting signature, since we do not use that value
            # for this test. However, those are mostly Wycheproof vectors that use the
            # same key and message for a lot of tests, which is not useful for testing
            # the invariant.
            if test.type != TestType.VALID:
                continue

            key = _encode_key(key_encoding, curve, test.d)
            if hash_function is not None:
                digest = hashes.Hash(hash_function.get_hash_instance())
                digest.update(test.msg)
                msg = digest.finalize()
            else:
                msg = test.msg

            data = SigGenData(key, msg)
            info = TestInfo.new_from_test(test, vectors.compliance, data)

            try:
                data.ret_sig = sign(key, msg)
            except NotImplementedError:
                logger.error(
                    "ECDSA sign not implemented for curve=%s, hash=%s, skipped test",
                    str(curve),
                    str(hash_function),
                )
                return rd
            except Exception as error:
                logger.debug("Caught exception", exc_info=True)
                info.fail(f"Exception raised: {str(error)}")
                results.add(info)
                continue

            _key = ec.derive_private_key(
                int.from_bytes(test.d, "big"), curve.get_curve_instance()
            )
            _pubkey = _key.public_key().public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint,
            )
            pubkey = _encode_pubkey(pubkey_encoding, curve, _pubkey)

            try:
                ret_ver = verify(pubkey, msg, data.ret_sig)
            except NotImplementedError:
                logger.error(
                    "ECDSA verify not implemented for curve=%s, hash=%s, skipped test",
                    str(curve),
                    str(hash_function),
                )
                return rd
            except Exception as error:
                logger.debug("Caught exception", exc_info=True)
                info.fail(f"Exception raised: {str(error)}")
                results.add(info)
                continue

            if ret_ver:
                info.ok()
            else:
                info.fail("Signature rejected")
            results.add(info)

    # results = Results.new(
    #     (
    #         "Test signature generation and verification consecutively"
    #         " with randomly generated values."
    #     ),
    #     ["curve", "key_encoding", "pubkey_encoding", "hash_function"],
    # )
    # results.add_notes({"RandomTest": "Test values are randomly generated."})
    # rd.add(results)
    #
    # for i in track(range(10), rf"\[{curve}] Test sign then verify"):
    #     # Generate a fixed key.
    #     _key = ec.generate_private_key(curve.get_curve_instance())
    #     d = _key.private_numbers().private_value
    #     key = _encode_key(
    #         key_encoding, curve, d.to_bytes((d.bit_length() + 7) // 8, "big")
    #     )
    #     _pubkey = _key.public_key()
    #     pubkey = _encode_pubkey(
    #         pubkey_encoding,
    #         curve,
    #         _pubkey.public_bytes(
    #             serialization.Encoding.X962,
    #             serialization.PublicFormat.UncompressedPoint,
    #         ),
    #     )
    #
    #     for tid in range(i * 100, (i + 1) * 100):
    #         info = TestInfo.new(tid, TestType.VALID, ["RandomTest"])
    #         message = random.randbytes(512 + tid)
    #         if hash_function:
    #             digest = hashes.Hash(hash_function.get_hash_instance())
    #             digest.update(message)
    #             message = digest.finalize()
    #
    #         data = SigGenData(key, message)
    #         try:
    #             signature = sign(key, message)
    #             data.sig = signature
    #         except Exception as error:
    #             info.fail(f"Signing failed: {str(error)}", data)
    #             logger.debug("Error running sign function", exc_info=True)
    #             results.add(info)
    #             continue
    #
    #         try:
    #             res = verify(pubkey, message, signature)
    #         except Exception as error:
    #             info.fail(f"Signature verification failed: {str(error)}", data)
    #             logger.debug("Error running verify function", exc_info=True)
    #             results.add(info)
    #             continue
    #
    #         if res:
    #             info.ok(data)
    #             results.add(info)
    #             continue
    #
    #         # TODO: check whether signature is actually valid to set a more precise
    #         # error reason.
    #         info.fail("Signature is not valid or verification is incorrect", data)

    return rd


def test_key_pair_gen(
    keygen: Keygen, curve: Curve, num_keys: int = 5000
) -> ResultsDict:
    """Tests a function that generates ECDSA key pairs.

    Calls `keygen` to generate `num_keys` keys in the format defined by :data:`KeyPair`.
    There are three checks in this test. First, the private key is derived from the
    private value to verify it works for the given curve. Then, if the public key is
    included, it must match the private key. Finally, all private keys are concatenated
    and tested with :mod:`crypto_condor.primitives.TestU01` to check for potential
    biases.

    .. deprecated:: FIXME(version)
        This function is being replaced by :func:`test_keygen`, which complies with the
        newly introduced minimum data size for TestU01.

    Args:
        keygen:
            The function that generates ECDSA key pairs. See :protocol:`KeyGen` for the
            expected signature of this function.
        curve:
            The elliptic curve to use.

    Keyword Args:
        num_keys:
            The number of keys to generate. The more data is available for TestU01, the
            more chances of catching any bias present. A minimum of 5000 keys, which
            results in roughly 1 million bits on ``P-224``, is enforced.

    Returns:
        A dictionary containing two :class:`Results`, one for the results of generating
        key pairs and one for the results of the TestU01 battery.

    Raises:
        ValueError:
            If ``num_keys`` is less than 5000.

    Example:
        Let's test PyCryptodome's key generation. We import the ECDSA module.

        >>> from crypto_condor.primitives import ECDSA

        We pick the curve P-224.

        >>> curve = ECDSA.Curve.P224

        Then wrap the implementation to match the signature defined by
        :protocol:`KeyGen`.

        >>> from Crypto.PublicKey import ECC
        >>> def my_key_gen() -> tuple[int, int, int]:
        ...     key = ECC.generate(curve=str(curve))
        ...     return (int(key.d), int(key.pointQ.x), int(key.pointQ.y))

        And test it.

        >>> results_dict = ECDSA.test_key_pair_gen(my_key_gen, curve)
        Generating keys ...
        >>> assert results_dict.check()
    """
    rd = ResultsDict()

    if num_keys < 5000:
        raise ValueError(f"This test requires at least 5000 keys (got {num_keys})")

    keygen_results = Results.new("Tests key pair generation", ["curve", "num_keys"])
    rd.add(keygen_results)

    keys = list()
    ec_curve = curve.get_curve_instance()

    for tid in track(range(num_keys), "Generating keys"):
        info = TestInfo.new(tid, TestType.VALID, ["RandomTest"])
        try:
            key = keygen()
        except Exception as error:
            # Since no inputs are given to keygen() and we do not check the output just
            # yet, any errors running this function are considered fatal, thus we log
            # the exception and return the (empty) ResultsDict immediately.
            logger.exception(
                "Failed to run ECDSA key generation for curve %s", str(curve)
            )
            logger.warning("ECDSA %s key generation test stopped", str(curve))
            info.fail(f"Key generation failed: {str(error)}")
            keygen_results.add(info)
            return rd

        # Verification of the private and public values happens here. If something
        # fails, call info.fail(), add the result, and continue.
        # Otherwise, d and info must be correctly set after the match.
        match key:
            case int() as d:
                data = KeyGenData(d)
                # Only check if d can be used to derive a private key, no public key
                # check to perform.
                try:
                    sk = ec.derive_private_key(d, ec_curve)
                except (TypeError, ValueError) as error:
                    info.fail(f"Failed to derive private key: {str(error)}", data)
                    keygen_results.add(info)
                    continue
            case (int() as d, int() as qx, int() as qy):
                data = KeyGenData(d, qx, qy)
                # Same as above, derive private key.
                try:
                    sk = ec.derive_private_key(d, ec_curve)
                except (TypeError, ValueError) as error:
                    info.fail(f"Failed to derive private key: {str(error)}", data)
                    keygen_results.add(info)
                    continue
                # But also check public key.
                pk = sk.public_key()
                pk_num = pk.public_numbers()
                if qx != pk_num.x and qy != pk_num.y:
                    info.fail("Wrong public coordinates", data)
                elif qx != pk_num.x:
                    info.fail("Wrong public x-coordinate", data)
                elif qy != pk_num.y:
                    info.fail("Wrong public y-coordinate", data)
            case bytes():
                # Load the private key. If it works, we assume the value is correct and
                # just add it to the rest.
                sk = _load_pem_or_der(key)
                sk_num = sk.private_numbers()
                d = sk_num.private_value
                # For verifying the public coordinates, we go through public_numbers()
                # and the public_key(), as it seems to perform the validation.
                # NOTE: this may be unnecessary depending on the check performed by the
                # loading function, but the documentation doesn't mention any validation
                # other than the data structure.
                pk_num = sk_num.public_numbers
                data = KeyGenData(d, pk_num.x, pk_num.y)
                try:
                    _ = pk_num.public_key()
                except ValueError:
                    info.fail("Public key is invalid for the curve", data)
                    keygen_results.add(info)
                    continue
                # TODO: is it useful/necessary to check that the values in pk_num are
                # equal to those of sk.public_key().public_numbers()?
            case _:
                info.fail("Failed to parse return value of keygen")
                keygen_results.add(info)
                continue

        info.ok(data)
        keygen_results.add(info)
        keys.append(d)

    match curve:
        # TODO: review this.
        case Curve.P521 | Curve.B283 | Curve.B409 | Curve.B571:
            bits = "".join(bin(key)[2:] for key in keys)
            if end := len(bits) % 32:
                bits = bits[:-end]
            assert len(bits) % 32 == 0, f"{len(bits) = }, {len(bits) % 32 = }"
            b_keys = bytes(int(bits[i : i + 8], 2) for i in range(0, len(bits), 8))
        case _:
            b_keys = b"".join(key.to_bytes(curve.key_size // 8, "big") for key in keys)

    if len(b_keys) <= 0:
        logger.error("No keys saved for TestU01 test, possible parsing error")
        # TODO: add hint on enabling debug logging.
        return rd
    if len(b_keys) % 4 != 0:
        logger.error("Total length of keys is not a multiple of 4 bytes")
        return rd

    with tempfile.NamedTemporaryFile("wb") as fp:
        written = fp.write(b_keys)
        if written <= 0:
            logger.error("no bytes written")
        elif written < 500:
            logger.error("too few bits")
        testu01_result = TestU01.test_file(fp.name)

    rd |= testu01_result
    return rd


def test_keygen(keygen: Keygen, curve: Curve, nbytes: int = 10_000_000) -> ResultsDict:
    """Tests a function that generates ECDSA key pairs.

    Calls ``keygen`` enough times to generate ``nbytes`` of private key material. This
    test verifies some conditions on the keys:

    * If the private key is an int, the test derives an elliptic curve key.
    * If the public key coordinates are included, the test derives the public key and
      checks that the coordinates match.
    * If the key is in bytes, the test loads it and checks that the public key
      corresponds to the private key.

    If any of these conditions fail, the individual test for that key is marked as
    failed. Otherwise, the private key values are converted to bytes, concatenated, and
    tested with TestU01.

    .. important::

        This aims to look for poor randomness generation **but some tests can fail**:
        TestU01 checks for uniformly random numbers, elliptic curve private keys are
        chosen modulo the order of the curve. In particular, the curves for which the
        size in bits of its order is not a multiple of 8 fail faster if the keys are
        simply converted from int to bytes. Our approach is to convert to a binary
        representation, removing the leading zeroes, concatenating in binary form, and
        then converting to bytes for writing. This is a best-effort attempt to try and
        distinguish from a correct key generator that fails some tests and a poor
        entropy source that fails most of them at 100KB of keys.

    Args:
        keygen:
            The key generation function to test.
        curve:
            The elliptic curve used by ``keygen``. This is used to derive the private
            key from the private value, or used to verify that the key in DER or PEM
            format is on the right curve.
        nbytes:
            The number of bytes to generate. TestU01 requires at least 100 000 bytes:
            enough keys are generated to fill a buffer of size ``nbytes`` with the
            private key values.

    Returns:
        A dictionary with two :class:`Results`, one with individual tests for each key
        and one for the tests from TestU01.

    Raises:
        ValueError:
            If ``nbytes`` is less than 100 000.
    """
    if nbytes < 100_000:
        raise ValueError(f"TestU01 requires at least 100 000 bytes, got {nbytes}")

    from math import ceil

    from crypto_condor.primitives import TestU01

    # The key size in bytes.
    ksize = (curve.key_size + 7) // 8
    # Total number of keys to generate to fill nbytes.
    nkeys = ceil(nbytes / ksize)

    results = ResultsDict()
    res = Results.new("Tests correct key pair generation", ["curve", "nbytes"])
    results.add(res)

    keys = list()
    ec_curve = curve.get_curve_instance()

    for i in track(range(1, nkeys + 1), "Testing keygen"):
        info = TestInfo.new(i, TestType.VALID)

        try:
            out = keygen()
        except Exception as error:
            info.fail(f"Failed to run ECDSA keygen: {error}")
            res.add(info)
            continue

        # TODO: if public key verification fails, don't add secret key to output?
        match out:
            case [int() as d]:
                data = KeyGenData(d, None, None)
                try:
                    sk = ec.derive_private_key(d, ec_curve)
                except (TypeError, ValueError) as error:
                    info.fail(f"Failed to derive private key: {error}", data)
                    res.add(info)
                    continue

            case [int() as d, int() as qx, int() as qy]:
                data = KeyGenData(d, qx, qy)
                try:
                    sk = ec.derive_private_key(d, ec_curve)
                except (TypeError, ValueError) as error:
                    info.fail(f"Failed to derive private key: {error}", data)
                    res.add(info)
                    continue
                # Check the public key.
                pk = sk.public_key()
                pk_num = pk.public_numbers()
                if qx != pk_num.x and qy != pk_num.y:
                    info.fail("Wrong public coordinates", data)
                elif qx != pk_num.x:
                    info.fail("Wrong public x-coordinate", data)
                elif qy != pk_num.y:
                    info.fail("Wrong public y-coordinate", data)

            case [bytes() as key]:
                try:
                    sk = _load_pem_or_der(key)
                except (TypeError, ValueError) as error:
                    # TODO: include the key for debugging.
                    info.fail(f"Failed to derive private key: {error}")
                    res.add(info)
                    continue
                if sk.curve != ec_curve:
                    err_msg = (
                        f"Key is on another curve: expected {str(curve)},"
                        f" got {sk.curve.name}"
                    )
                    info.fail(err_msg)
                    res.add(info)
                    continue
                sk_numbers = sk.private_numbers()
                d = sk_numbers.private_value
                pk_numbers = sk_numbers.public_numbers
                data = KeyGenData(d, pk_numbers.x, pk_numbers.y)
                # AFAIK, loading a key does not verify that the public part is valid. By
                # explicitly calling public_key() it will if it's invalid.
                try:
                    _ = pk_numbers.public_key()
                except ValueError:
                    info.fail(f"Public key is invalid for {str(curve)}", data)

        info.ok(data)
        res.add(info)
        keys.append(d)

    if not keys:
        logger.error("No private keys saved for TestU01, likely from parsing errors")
        logger.error("Hint: check results with debug data")
        return results

    match curve:
        # TODO: review this.
        case Curve.P521 | Curve.B283 | Curve.B409 | Curve.B571:
            bits = "".join(bin(key)[2:] for key in keys)
            if end := len(bits) % 32:
                bits = bits[:-end]
            assert len(bits) % 32 == 0, f"{len(bits) = }, {len(bits) % 32 = }"
            b_keys = bytes(int(bits[i : i + 8], 2) for i in range(0, len(bits), 8))
        case _:
            b_keys = b"".join(key.to_bytes(curve.key_size // 8, "big") for key in keys)

    results |= TestU01.test_raw(b_keys)
    return results


# -------------------------------------------------------------------------------------
# Output test
# -------------------------------------------------------------------------------------


def verify_file(
    filename: str,
    pubkey_encoding: PubKeyEncoding,
    hash_function: Hash,
    curve: Curve | None,
) -> ResultsDict:
    r"""Verifies signatures contained in a file.

    Signatures are read from the file and then verified with a reference implementation.
    The file must have the following format:

    Format:
        - One set of arguments per line.
        - Lines are separated by newlines (``\n``).
        - Lines that start with '#' are counted as comments and ignored.
        - Arguments are written in hexadecimal and separated by slashes.
        - The keys may be different for each line but they must be encoded in the same
          format.
        - The order of the arguments is:

        .. code::

            pub_key/message/signature

    Args:
        filename:
            The name of the path containing the signatures to verify.
        pubkey_encoding:
            The encoding of the public keys used.
        hash_function:
            The hash function used to generate the signatures.
        curve:
            The elliptic curve of the keys. This argument is required when the public
            key encoding is UNCOMPRESSED, otherwise it is ignored.

    Returns:
        A dictionary of results.

    .. deprecated:: TODO(version)
        Will be removed in a future version, use :func:`test_output_sign` instead.
    """
    warnings.warn("Use test_output_sign instead", DeprecationWarning, stacklevel=1)
    return test_output_sign(filename, curve, hash_function, pubkey_encoding)


def test_output_sign(
    filename: str,
    curve: Curve | None,
    hash_function: Hash,
    pubkey_encoding: PubKeyEncoding,
) -> ResultsDict:
    r"""Verifies signatures contained in a file.

    Signatures are read from the file and then verified with a reference implementation.
    The file must have the following format:

    Format:
        - One set of arguments per line.
        - Lines are separated by newlines (``\n``).
        - Lines that start with '#' are counted as comments and ignored.
        - Arguments are written in hexadecimal and separated by slashes.
        - The keys may be different for each line but they must be encoded in the same
          format.
        - The order of the arguments is:

        .. code::

            pub_key/message/signature

    Args:
        filename:
            The name of the path containing the signatures to verify.
        curve:
            The elliptic curve of the keys. This argument is required when the public
            key encoding is UNCOMPRESSED, otherwise it is ignored.
        hash_function:
            The hash function used to generate the signatures.
        pubkey_encoding:
            The encoding of the public keys used.

    Returns:
        A dictionary of results. The results of verifying each signature with an
        internal implementation. Errors, including parsing ones, are counted as failures
        and do not raise exceptions, except for the IOError indicated below.

        For parsing errors, the line numbering starts at 1.

    .. testsetup:: *

        from pathlib import Path
        from crypto_condor.primitives import ECDSA
        all_vectors = ECDSA._load_vectors(ECDSA.VectorType.SIGVER, ECDSA.Curve.P256, ECDSA.Hash.SHA256, True, True)
        valid = list()
        for vectors in all_vectors:
            for test in vectors.tests:
                if test.type != "valid":
                    continue
                valid.append(f"{test.pubkey.hex()}/{test.msg.hex()}/{test.sig.hex()}")
        file = Path("/tmp/ecdsa-p256-sha256-signatures.txt")
        text = "\n".join(valid)
        file.write_text(text)

    Example:
        We start by importing the ECDSA module.

        >>> from crypto_condor.primitives import ECDSA

        For this example we already have a correctly formatted file. We print the first
        line to show the format, then split the arguments for clarity.

        >>> filename = "/tmp/ecdsa-p256-sha256-signatures.txt"
        >>> with open(filename, "r") as fd:
        ...     line = fd.readline().strip()
        ...     args = line.split("/")
        ...     print(line)
        ...     print(f"key = {args[0]}")
        ...     print(f"msg = {args[1]}")
        ...     print(f"sig = {args[2]}")
        04e424dc61d4bb3cb7ef4344a7f8957a0c5134e16f7a67c074f82e6e12f49abf3c970eed7aa2bc48651545949de1dddaf0127e5965ac85d1243d6f60e7dfaee927/e1130af6a38ccb412a9c8d13e15dbfc9e69a16385af3c3f1e5da954fd5e7c45fd75e2b8c36699228e92840c0562fbf3772f07e17f1add56588dd45f7450e1217ad239922dd9c32695dc71ff2424ca0dec1321aa47064a044b7fe3c2b97d03ce470a592304c5ef21eed9f93da56bb232d1eeb0035f9bf0dfafdcc4606272b20a3/3045022100bf96b99aa49c705c910be33142017c642ff540c76349b9dab72f981fd9347f4f022017c55095819089c2e03b9cd415abdf12444e323075d98f31920b9e0f57ec871c
        key = 04e424dc61d4bb3cb7ef4344a7f8957a0c5134e16f7a67c074f82e6e12f49abf3c970eed7aa2bc48651545949de1dddaf0127e5965ac85d1243d6f60e7dfaee927
        msg = e1130af6a38ccb412a9c8d13e15dbfc9e69a16385af3c3f1e5da954fd5e7c45fd75e2b8c36699228e92840c0562fbf3772f07e17f1add56588dd45f7450e1217ad239922dd9c32695dc71ff2424ca0dec1321aa47064a044b7fe3c2b97d03ce470a592304c5ef21eed9f93da56bb232d1eeb0035f9bf0dfafdcc4606272b20a3
        sig = 3045022100bf96b99aa49c705c910be33142017c642ff540c76349b9dab72f981fd9347f4f022017c55095819089c2e03b9cd415abdf12444e323075d98f31920b9e0f57ec871c

        We use :func:`test_output_sign` to test this file. In this case the keys are
        DER-encoded and we used SHA-256 to hash the messages.

        >>> result = ECDSA.test_output_sign(
        ...     filename,
        ...     ECDSA.Curve.P256,
        ...     ECDSA.Hash.SHA256,
        ...     ECDSA.PubKeyEncoding.UNCOMPRESSED,
        ... )
        [P-256][SHA-256] Test signatures from file ...

    .. versionadded:: TODO(version)
        Replaces :func:`verify_file`.
    """  # noqa: E501
    rd = ResultsDict()

    if pubkey_encoding == PubKeyEncoding.UNCOMPRESSED and curve is None:
        logger.error("Curve required when using uncompressed points are public keys")
        return rd

    try:
        with open(filename, "r") as file:
            lines = file.readlines()
    except IOError:
        logger.exception("Could not read file %s", str(filename))
        return rd

    results = Results.new(
        "Test signatures from a file", ["filename", "pubkey_encoding", "hash_function"]
    )
    rd.add(results)

    for tid, line in track(
        enumerate(lines, start=1),
        rf"\[{curve}]\[{hash_function}] Test signatures from file",
    ):
        if line.startswith("#"):
            continue
        info = TestInfo.new(tid, TestType.VALID, ["UserInput"])

        match line.rstrip().split("/"):
            case (k, m, s):
                try:
                    key, msg, sig = map(bytes.fromhex, (k, m, s))
                except ValueError as error:
                    info.fail(f"Error parsing line {tid}: {str(error)}")
                    results.add(info)
                    continue
            case _ as args:
                info.fail(
                    f"Error parsing line {tid}: got {len(args)} arguments, expected 3"
                )
                results.add(info)
                continue

        # Re-encode to DER if necessary.
        match pubkey_encoding:
            case PubKeyEncoding.DER:
                pass
            case PubKeyEncoding.PEM:
                imported_key = serialization.load_pem_public_key(key, None)
                key = imported_key.public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            case PubKeyEncoding.UNCOMPRESSED:
                # TYPE: Ignoring mypy because curve is not be None because of the check
                # above.
                pk = ec.EllipticCurvePublicKey.from_encoded_point(
                    curve.get_curve_instance(), key  # type: ignore
                )
                key = pk.public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )

        data = SigVerData(key, msg, sig)
        info.data = data

        try:
            if _verify(key, hash_function, msg, sig):
                info.ok()
            else:
                info.fail("Invalid signature")
        except ValueError as error:
            logger.debug("Error verifying signature %s" % str(tid), exc_info=True)
            info.fail(f"Failed to verify signature: {str(error)}")
        finally:
            results.add(info)

    return rd


# -------------------------------------------------------------------------------------
# Utils
# -------------------------------------------------------------------------------------


@attrs.define
class FuncParams:
    """Result from parsing a harness function's name.

    Args:
        op:
            The operation performed.
        curve:
            The elliptic curve.
        algo:
            The hash algorithm.
        sk_enc:
            The private key encoding.
        pk_enc:
            The public key encoding.
        prehash:
            Whether the messages should be hashed before.
    """

    op: str
    curve: Curve
    algo: Hash | None = None
    sk_enc: KeyEncoding | None = None
    pk_enc: PubKeyEncoding | None = None
    prehash: bool = False


def _parse_function_name(name: str) -> FuncParams | None:
    """Parses function names to extract the arguments.

    Returns:
        An instance of :class:`FuncParams` with the results of the parsing, or None if
        an error occurred. This can include an invalid operation, invalid argument (e.g.
        invalid curve name), or options other than `prehash`.

    Note:
        Since the function name is necessary to test harnesses, parsing errors are
        reported using `logger.error`. Values are tested one by one to have accurate
        error messages.
    """
    match name.split("_"):
        case ["CC", "ECDSA", "keygen", _curve]:
            try:
                curve = Curve.from_name(_curve)
            except ValueError:
                logger.error("Invalid curve %s for ECDSA", _curve)
                return None
            return FuncParams("keygen", curve)

        case [
            "CC",
            "ECDSA",
            ("sign" | "verify" | "signthenver") as op,
            _curve,
            _hash,
            _enc,
            *opts,
        ]:
            try:
                curve = Curve.from_name(_curve)
            except ValueError:
                logger.error("Invalid curve %s for ECDSA", _curve)
                return None
            try:
                algo = Hash.from_name(_hash)
            except ValueError:
                logger.error("Invalid hash function %s for ECDSA", _hash)
                return None

            if op == "sign":
                try:
                    sk_enc = KeyEncoding(_enc)
                    pk_enc = None
                except ValueError:
                    logger.error("Invalid private key encoding %s for ECDSA", _enc)
                    return None
            elif op == "verify":
                try:
                    sk_enc = None
                    pk_enc = PubKeyEncoding(_enc)
                except ValueError:
                    logger.error("Invalid public key encoding %s for ECDSA", _enc)
                    return None
            else:
                # FIXME: deal with signthenver
                return None

            if len(opts) >= 2:
                logger.error("Too many options in ECDSA harness function %s", name)
                return None

            if not opts:
                prehash = False
            elif opts[0] == "prehash":
                prehash = True
            else:
                logger.error(
                    "Invalid option %s in ECDSA harness function %s", opts[0], name
                )
                return None

            return FuncParams(op, curve, algo, sk_enc, pk_enc, prehash)

        case ["CC", "ECDSA", op]:
            logger.error("Invalid operation %s for ECDSA harness", op)
            return None
        case _:
            return None


# -------------------------------------------------------------------------------------
# Python harness
# -------------------------------------------------------------------------------------


def test_wrapper_python(
    wrapper: Path, compliance: bool, resilience: bool
) -> ResultsDict:
    """Tests a Python SHA wrapper.

    Args:
        wrapper:
            A path to the wrapper to test.
        compliance:
            Whether to use compliance test vectors.
        resilience:
            Whether to use resilience test vectors.
    """
    ecdsa_wrapper = _load_python_harness(wrapper)

    rd = ResultsDict()

    for name, func in inspect.getmembers(ecdsa_wrapper, inspect.isfunction):
        params = _parse_function_name(name)
        if params is None:
            # Error message should have been emitted by _parse_function_name so we just
            # continue.
            continue
        match params.op:
            case "sign":
                rd |= test_sign(
                    func,
                    params.curve,
                    params.algo,  # type: ignore
                    params.sk_enc,  # type: ignore
                    pre_hashed=params.prehash,
                    compliance=compliance,
                    resilience=resilience,
                )
            case "verify":
                rd |= test_verify(
                    func,
                    params.curve,
                    params.algo,  # type: ignore
                    params.pk_enc,  # type: ignore
                    pre_hashed=params.prehash,
                    compliance=compliance,
                    resilience=resilience,
                )
            case "signthenver":
                sign_name = f"CC_ECDSA_sign_{str(params.curve)}_{str(params.algo)}_{str(params.sk_enc)}"  # noqa: E501
                ver_name = f"CC_ECDSA_verify_{str(params.curve)}_{str(params.algo)}_{str(params.pk_enc)}"  # noqa: E501
                if params.prehash:
                    sign_name += "_prehash"
                    ver_name += "_prehash"
                sign_func = getattr(ecdsa_wrapper, sign_name, None)
                ver_func = getattr(ecdsa_wrapper, ver_name, None)
                if sign_func is None:
                    logger.error("Did not find %s to test sign-then-verify", sign_name)
                    continue
                if ver_func is None:
                    logger.error("Did not find %s to test sign-then-verify", ver_name)
                    continue
                rd |= test_sign_verify_invariant(
                    sign_func,
                    ver_func,
                    params.curve,
                    params.algo,  # type: ignore
                    params.sk_enc,  # type: ignore
                    params.pk_enc,  # type: ignore
                )
            case "keygen":
                rd |= test_keygen(func, params.curve)
            case _:
                pass

    return rd


# -------------------------------------------------------------------------------------
# C harness
# -------------------------------------------------------------------------------------


def _test_harness_sign(
    ffi: cffi.FFI,
    lib,
    function: str,
    params: FuncParams,
    compliance: bool,
    resilience: bool,
):
    logger.info("Testing harness function %s", function)

    ffi.cdef(
        f"""int {function}(uint8_t *sig, size_t *sig_size,
                           const uint8_t *sk, size_t sk_size,
                           const uint8_t *msg, size_t msg_size);
        """
    )
    sign = getattr(lib, function)

    def _sign(sk: bytes, msg: bytes) -> bytes:
        c_sk = ffi.new("uint8_t[]", sk)
        c_msg = ffi.new("uint8_t[]", msg)
        # ECDSA signatures are at least twice the size of the private key: the (r,s)
        # integers are the same size as the private key, but different encodings add
        # some overhead. For DER-encoded signatures, the overhead is 6 bytes (SEQUENCE +
        # size + 2 * (INTEGER + size)). Additionally, ASN.1 integers are signed so if r
        # or s is equal or greater than 2^{256-1}, a \x00 byte is placed to the left to
        # avoid it being interpreted as negative.
        # https://crypto.stackexchange.com/a/50719
        # Leaving no margin _can_ fail, but proper DER-encoded signatures should fit, so
        # implementations should fail gracefully to avoid crashing CC and making the
        # test count as failed. This is a reason why CC passes the length of the buffers
        # to the function.
        sig_size = 2 * ((params.curve.key_size + 7) // 8) + 6 + 2
        c_sig = ffi.new(f"uint8_t[{sig_size}]")
        c_sig_size = ffi.new("size_t[1]")
        c_sig_size[0] = sig_size
        rc = sign(c_sig, c_sig_size, c_sk, len(sk), c_msg, len(msg))
        if rc != 1:
            raise ValueError(f"{function} failed with code {rc}")
        return bytes(c_sig)[: int(c_sig_size[0])]

    return test_sign(
        _sign,
        params.curve,
        params.algo,  # type: ignore
        params.sk_enc,  # type: ignore
        pre_hashed=params.prehash,
        compliance=compliance,
        resilience=resilience,
    )


def _test_harness_verify(
    ffi: cffi.FFI,
    lib,
    function: str,
    params: FuncParams,
    compliance: bool,
    resilience: bool,
):
    logger.info("Testing harness function %s", function)

    ffi.cdef(
        f"""
        int {function}(const uint8_t *pk, const size_t pk_size,
                       const uint8_t *msg, const size_t msg_size,
                       const uint8_t *sig, const size_t sig_size);
    """
    )
    verify = getattr(lib, function)

    def _verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
        c_pk = ffi.new("uint8_t[]", pk)
        c_msg = ffi.new("uint8_t[]", msg)
        c_sig = ffi.new("uint8_t[]", sig)
        rc = verify(c_pk, len(pk), c_msg, len(msg), c_sig, len(sig))
        if rc == 1:
            return True
        elif rc == 0:
            return False
        else:
            raise ValueError(f"{function} failed with code {rc}")

    return test_verify(
        _verify,
        params.curve,
        params.algo,  # type: ignore
        params.pk_enc,  # type: ignore
        pre_hashed=params.prehash,
        compliance=compliance,
        resilience=resilience,
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
            A list of ``CC_ECDSA`` functions to test.
        compliance:
            Whether to use compliance test vectors.
        resilience:
            Whether to use resilience test vectors.
    """
    logger.info("Found ECDSA harness functions: %s", ", ".join(functions))

    rd = ResultsDict()

    for function in functions:
        params = _parse_function_name(function)
        if params is None:
            continue
        match params.op:
            case "sign":
                rd |= _test_harness_sign(
                    ffi, lib, function, params, compliance, resilience
                )
            case "verify":
                rd |= _test_harness_verify(
                    ffi, lib, function, params, compliance, resilience
                )
            case "signthenver":
                sign_name = f"CC_ECDSA_sign_{str(params.curve)}_{str(params.algo)}_{str(params.sk_enc)}"  # noqa: E501
                ver_name = f"CC_ECDSA_verify_{str(params.curve)}_{str(params.algo)}_{str(params.pk_enc)}"  # noqa: E501
                if params.prehash:
                    sign_name += "_prehash"
                    ver_name += "_prehash"
                if sign_name not in functions:
                    logger.error("Did not find %s to test sign-then-verify", sign_name)
                    continue
                if ver_name not in functions:
                    logger.error("Did not find %s to test sign-then-verify", ver_name)
                    continue
                # FIXME: finish this.
            case "keygen":
                # TODO
                pass

    return rd


# -------------------------------------------------------------------------------------
# Harness
# -------------------------------------------------------------------------------------


def test_harness(harness: Path, compliance: bool, resilience: bool) -> ResultsDict:
    """Tests an ECDSA harness.

    Args:
        harness:
            The harness to test.
        compliance:
            Whether to use compliance test vectors.
        resilience:
            Whether to use resilience test vectors.

    Raises:
        FileNotFoundError:
            If the harness is not found.
    """
    if not harness.is_file():
        raise FileNotFoundError(f"harness {str(harness)} not found")

    match harness.suffix:
        case ".py":
            return test_wrapper_python(harness, compliance, resilience)
        case _:
            raise ValueError(f"No test for '{harness.suffix}' harness")
