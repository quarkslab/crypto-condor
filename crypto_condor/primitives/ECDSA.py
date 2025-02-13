"""Test ECDSA implementations."""

from __future__ import annotations

import importlib
import logging
import random
import sys
import tempfile
from pathlib import Path
from typing import Protocol, TypeAlias

import attrs
import strenum
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    Prehashed,
    encode_dss_signature,
)
from rich.progress import track

from crypto_condor.primitives import TestU01
from crypto_condor.primitives.common import DebugInfo, Results, ResultsDict, TestType
from crypto_condor.vectors.ECDSA import (
    Curve,
    EcdsaSigGenVectors,
    EcdsaSigVerVectors,
    Hash,
)

logger = logging.getLogger(__name__)


def __dir__():  # pragma: no cover
    """Defines the public API of the module.

    Useful to define the available auto-completions by IDEs.
    """
    return [
        # Type aliases
        "KeyPair",
        # Protocols
        Verify.__name__,
        Sign.__name__,
        KeyGen.__name__,
        # Enums
        KeyEncoding.__name__,
        PubKeyEncoding.__name__,
        Wrapper.__name__,
        # Exceptions
        EcdsaError.__name__,
        PubKeyImportError.__name__,
        # Dataclasses
        # SigData.__name__,
        # KeyGenData.__name__,
        # Test functions
        verify_file.__name__,
        test_verify.__name__,
        test_sign.__name__,
        test_sign_then_verify.__name__,
        test_key_pair_gen.__name__,
        run_wrapper.__name__,
        # Imported
        Curve.__name__,
        Hash.__name__,
    ]


# --------------------------- Type aliases --------------------------------------------

KeyPair: TypeAlias = tuple[int, int | None, int | None]
"""Represents a private ECDSA key.

Contains either (d, qx, qy) or (d, None, None) where ``d`` is the private value, and qx
and qy are the coordinates of the public value.
"""

# ---------------------- Protocols ----------------------------------------------------


class Verify(Protocol):
    """Represents a function that verifies ECDSA signatures."""

    def __call__(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verifies an ECDSA signature.

        Args:
            public_key: The public elliptic curve key. Either PEM-encoded, DER-encoded,
                or as serialized int.
            message: The signed message.
            signature: The resulting signature.

        Returns:
            True if the signature is valid, False otherwise.
        """
        ...  # pragma: no cover (protocol)


class Sign(Protocol):
    """Represents a function that signs a message with ECDSA."""

    def __call__(self, private_key: bytes, message: bytes) -> bytes:
        """Signs a message with ECDSA.

        Args:
            private_key: The private elliptic curve key. Either PEM-encoded,
                DER-encoded, or as serialized int.
            message: The message to sign.


        Returns:
            The signed message.
        """
        ...  # pragma: no cover (protocol)


class KeyGen(Protocol):
    """Represents a function that generates ECDSA key pairs."""

    def __call__(self) -> KeyPair:
        """Generates an ECDSA key pair.

        Returns:
            A tuple (d, Qx, Qy) containing the private value ``d`` and the coordinates
            ``Qx`` and ``Qy`` of the public value, or a tuple (d, None, None) containing
            only the private value ``d``.
        """
        ...  # pragma: no cover (protocol)


# --------------------------- Enums ---------------------------------------------------


class KeyEncoding(strenum.StrEnum):
    """Supported key encodings."""

    PEM = "PEM"
    """The PEM encapsulation format, serialized to bytes."""
    DER = "DER"
    """The binary DER format."""
    INT = "INT"
    """The secret value, serialized to bytes."""


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


# --------------------------- Exceptions ----------------------------------------------


class EcdsaError(Exception):
    """Base ECDSA error."""

    pass


class PubKeyImportError(EcdsaError):
    """Exception raised when an error occurred while importing a public key."""

    pass


# --------------------------- Dataclasses ---------------------------------------------


@attrs.define
class SigData:
    """Debug data for signature generation or verification tests.

    Args:
        info: Common debug info, see :class:`crypto_condor.primitives.common.DebugInfo`.
        key: The key used.
        message: The message signed.
        signature: The signature produced or verified.
    """

    info: DebugInfo
    key: bytes
    message: bytes
    signature: bytes | None

    def __str__(self):
        """Returns string representation."""
        s = str(self.info)
        s += f"key = {self.key.hex()}\n"
        s += f"message = {self.message.hex()}\n"
        if self.signature is not None:
            s += f"signature = {self.signature.hex()}\n"
        else:
            s += "signature = <none>"
        return s


@attrs.define
class SigVerData:
    """Debug data for :func:`verify_file`.

    Similar to :class:`SigData`, the difference being that some attributes can be None,
    as a parsing error means we can't even get the key used for the operation.

    Args:
        info: Common debug info, see :class:`crypto_condor.primitives.common.DebugInfo`.
        key: The key used.
        message: The message signed.
        signature: The signature produced or verified.
    """

    info: DebugInfo
    key: bytes | None
    message: bytes | None
    signature: bytes | None

    def __str__(self):
        """Returns string representation."""
        s = str(self.info)
        if self.key is not None:
            s += f"key = {self.key.hex()}\n"
        if self.message is not None:
            s += f"message = {self.message.hex()}\n"
        if self.signature is not None:
            s += f"signature = {self.signature.hex()}\n"
        else:
            s += "signature = <none>"
        return s


@attrs.define
class KeyGenData:
    """Debug data for key generation tests.

    Args:
        info: Common debug info, see :class:`crypto_condor.primitives.common.DebugInfo`.
        d: The private value.
        qx: X-coordinate of the public point.
        qy: Y-coordinate of the public point.
    """

    info: DebugInfo
    d: int | None
    qx: int | None = None
    qy: int | None = None

    def __str__(self):
        """Returns string representation."""
        s = str(self.info)
        if self.d is not None:
            s += f"d = {self.d}\n"
        if self.qx is not None:
            s += f"Qx = {self.qx}\n"
            if self.qy is not None:
                s += f"Qy = {self.qy}\n"
        return s


# --------------------------- internal functions --------------------------------------


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
        e = PubKeyImportError("Couldn't load the public DER key")
        e.add_note(str(error))
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

    return True


# --------------------------- Test functions ------------------------------------------


def verify_file(
    filename: str, pubkey_encoding: PubKeyEncoding, hash_function: Hash
) -> Results:
    r"""Verifies signatures contained in a file.

    To test ECDSA signatures, the file must follow the format described below.

    Format:
        - One set of arguments per line.
        - Lines are separated by newlines (``\n``).
        - Lines that start with '#' are counted as comments and ignored.
        - Arguments are written in hexadecimal and separated by slashes.
        - The keys may be different for each line but they must be encoded in the same
          format.
        - The order of the arguments is:

        .. code::

            key/message/signature

    Args:
        filename: The name of the path containing the signatures to verify.
        pubkey_encoding: The encoding of the public keys used. Only DER- and PEM-encoded
            keys are supported.
        hash_function: The hash function used to generate the signatures.

    Returns:
        The results of verifying each signature with an internal implementation. Errors,
        including parsing ones, are counted as failures and do not raise exceptions,
        except for the IOError indicated below.

        For parsing errors, the line numbering starts at 1.

    Raises:
        IOError: If the file could not be read.

    .. testsetup:: *

        from pathlib import Path
        from crypto_condor.primitives import ECDSA
        vectors = ECDSA.EcdsaSigVerVectors.load(ECDSA.Curve.SECP256R1, ECDSA.Hash.SHA_256, compliance=False)
        valid = list()
        for group in vectors.wycheproof["testGroups"]:
            key = group["keyDer"]
            for test in group["tests"]:
                if test["result"] != "valid":
                    continue
                msg, sig = test["msg"], test["sig"]
                valid.append(f"{key}/{msg}/{sig}")
        file = Path("/tmp/ecdsa-p256-sha256-signatures.txt")
        text = "\n".join(valid)
        file.write_text(text)

    Example:
        We start by importing the ECDSA module.

        >>> from crypto_condor.primitives import ECDSA

        For this example we already have a correctly formatted: let's print the first
        line to show the format. The output is a bit long but we can see the three
        expected arguments: key, message, and signature.

        >>> filename = "/tmp/ecdsa-p256-sha256-signatures.txt"
        >>> with open(filename, "r") as fd:
        ...     print(fd.readline())
        3059301306072a8648ce3d020106082a8648ce3d030107034200042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e/313233343030/304402202ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e1802204cd60b855d442f5b3c7b11eb6c4e0ae7525fe710fab9aa7c77a67f79e6fadd76
        <BLANKLINE>

        We use :func:`verify_file` to test this file. In this case the keys are
        DER-encoded and we used SHA-256 to hash the messages. Since we know that it can
        raise ``IOError``, we wrap it in a try/except statement to print the error
        without crashing.

        >>> try:
        ...     result = ECDSA.verify_file(filename, ECDSA.PubKeyEncoding.DER, ECDSA.Hash("SHA-256"))
        ... except IOError as error:
        ...     print(error)
        Testing ...
    """  # noqa: E501
    try:
        with open(filename, "r") as file:
            lines = file.readlines()
    except IOError:
        logger.exception("Could not read file %s" % str(filename))
        raise

    results = Results(
        "ECDSA",
        "verify_file",
        "Tests signatures from a file",
        {
            "input_filename": filename,
            "pubkey_encoding": pubkey_encoding,
            "hash_function": hash_function,
        },
    )

    for tid, line in track(enumerate(lines, start=1), "Testing signatures"):
        if line.startswith("#"):
            continue
        info = DebugInfo(tid, TestType.VALID, ["UserInput"])

        match line.rstrip().split("/"):
            case (k, m, s):
                key, msg, sig = map(bytes.fromhex, (k, m, s))
            case _ as args:
                info.error_msg = (
                    f"Error parsing line {tid}, got {len(args)} arguments, expected 3"
                )
                results.add(SigVerData(info, None, None, None))
                continue

        # Re-encode to DER if necessary.
        match pubkey_encoding:
            case PubKeyEncoding.DER:
                pass
            case PubKeyEncoding.PEM:
                imported_key = serialization.load_pem_private_key(key, None)
                key = imported_key.public_key().public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            case PubKeyEncoding.UNCOMPRESSED:
                raise ValueError(
                    "PubKeyEncoding.UNCOMPRESSED is not supported for this function."
                )

        # Debug data
        data = SigVerData(info, key, msg, sig)
        try:
            if _verify(key, hash_function, msg, sig):
                info.result = True
            else:
                info.error_msg = "Invalid signature"
        except ValueError as error:
            logger.debug("Error verifying signature %s" % str(tid), exc_info=True)
            info.error_msg = f"Failed to verify signature: {str(error)}"
        results.add(data)

    return results


def _test_verify_nist(
    verify_function: Verify,
    curve: Curve,
    hash_function: Hash,
    pubkey_encoding: PubKeyEncoding,
    *,
    pre_hashed: bool = False,
) -> Results | None:
    """Tests a verifying function with NIST test vectors.

    Args:
        verify_function: The function to test, see :protocol:`Verify`.
        curve: The elliptic curve used.
        hash_function: The hash function used to generate the signatures.
        pubkey_encoding: A public key encoding accepted by the function.

    Keyword Args:
        pre_hashed: When True, the messages are hashed before passing them to
            :attr:`verify_function`.

    Returns:
        The results of the tests or None if there are no test vectors for the given
        curve and hash function.
    """
    vectors = EcdsaSigVerVectors.load(curve, hash_function, resilience=False)
    if vectors.nist is None:
        return None

    results = Results(
        "ECDSA",
        "test_verify (NIST)",
        "Runs NIST test vectors on the verifying function.",
        {
            "curve": curve,
            "hash_function": hash_function,
            "pubkey_encoding": pubkey_encoding,
        },
    )

    for test in track(vectors.nist.tests, "[NIST] Verifying signatures"):
        message = bytes.fromhex(test.message)
        # Encode signature from r and s.
        r = int(test.r, 16)
        s = int(test.s, 16)
        signature = encode_dss_signature(r, s)
        # Construct public key from Qx and Qy.
        if len(test.qx) % 2 == 1:
            qx = bytes.fromhex("0" + test.qx)
        else:
            qx = bytes.fromhex(test.qx)
        if len(test.qy) % 2 == 1:
            qy = bytes.fromhex("0" + test.qy)
        else:
            qy = bytes.fromhex(test.qy)
        encoded_point = b"\x04" + qx + qy

        match pubkey_encoding:
            case PubKeyEncoding.DER:
                pub_key = ec.EllipticCurvePublicKey.from_encoded_point(
                    curve.get_curve_instance(), encoded_point
                )
                key = pub_key.public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            case PubKeyEncoding.PEM:
                pub_key = ec.EllipticCurvePublicKey.from_encoded_point(
                    curve.get_curve_instance(), encoded_point
                )
                key = pub_key.public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            case PubKeyEncoding.UNCOMPRESSED:
                key = encoded_point

        if pre_hashed:
            digest = hashes.Hash(hash_function.get_hash_instance())
            digest.update(message)
            message = digest.finalize()

        test_type = TestType(test.result)
        info = DebugInfo(test.id, test_type, ["Compliance"], comment=test.fail_reason)
        data = SigData(info, key, message, signature)

        try:
            res = verify_function(key, message, signature)
        except Exception as error:
            if test_type == TestType.INVALID:
                info.result = True
            else:
                info.error_msg = f"Error running verify function: {str(error)}"
                logger.debug("Error running verify function", exc_info=True)
            results.add(data)
            continue

        match (test_type, res):
            case (TestType.VALID, True) | (TestType.INVALID, False):
                info.result = True
            case (TestType.VALID, False):
                info.error_msg = "Valid signature rejected"
            case (TestType.INVALID, True):
                info.error_msg = "Invalid signature accepted"

        results.add(data)

    return results


def _test_verify_wycheproof(
    verify_function: Verify,
    curve: Curve,
    hash_function: Hash,
    pubkey_encoding: PubKeyEncoding,
    *,
    pre_hashed: bool = False,
) -> Results | None:
    """Tests a verifying function with Wycheproof test vectors.

    Args:
        verify_function: The function to test, see :protocol:`Verify`.
        curve: The elliptic curve used.
        hash_function: The hash function used to generate the signatures.
        pubkey_encoding: A public key encoding accepted by the function.

    Keyword Args:
        pre_hashed: When True, the messages are hashed before passing them to
            :attr:`verify_function`.

    Returns:
        The results of the tests or None if there are no test vectors for the given
        curve and hash function.
    """
    vectors = EcdsaSigVerVectors.load(curve, hash_function, compliance=False)
    if vectors.wycheproof is None:
        return None

    results = Results(
        "ECDSA",
        "test_verify (Wycheproof)",
        "Runs Wycheproof test vectors on the verifying function.",
        {
            "curve": curve,
            "hash_function": hash_function,
            "pubkey_encoding": pubkey_encoding,
        },
    )
    results.add_notes(vectors.wycheproof["notes"])

    for group in track(
        vectors.wycheproof["testGroups"], "[Wycheproof] Verifying signatures"
    ):
        match pubkey_encoding:
            case PubKeyEncoding.DER:
                key = bytes.fromhex(group["keyDer"])
            case PubKeyEncoding.PEM:
                key = group["keyPem"].encode()
            case PubKeyEncoding.UNCOMPRESSED:
                key = bytes.fromhex(group["key"]["uncompressed"])
        for test in group["tests"]:
            tid = test["tcId"]
            test_type = TestType(test["result"])
            flags = test.get("flags", list())
            info = DebugInfo(tid, test_type, flags, comment=test.get("comment"))
            message = bytes.fromhex(test["msg"])
            signature = bytes.fromhex(test["sig"])
            if pre_hashed:
                digest = hashes.Hash(hash_function.get_hash_instance())
                digest.update(message)
                message = digest.finalize()
            data = SigData(info, key, message, signature)

            try:
                res = verify_function(key, message, signature)
            except Exception as error:
                if test_type == TestType.INVALID:
                    info.result = True
                else:
                    info.error_msg = f"Error running verify function: {str(error)}"
                    logger.debug("Error running verify function", exc_info=True)
                results.add(data)
                continue

            match (test_type, res):
                case (TestType.VALID, True) | (TestType.INVALID, False):
                    info.result = True
                case (TestType.VALID, False):
                    info.error_msg = "Valid signature rejected"
                case (TestType.INVALID, True):
                    info.error_msg = "Invalid signature accepted"
                case (TestType.ACCEPTABLE, (True | False)):
                    info.result = res

            results.add(data)

    return results


def test_verify(
    verify_function: Verify,
    curve: Curve,
    hash_function: Hash,
    pubkey_encoding: PubKeyEncoding,
    *,
    pre_hashed: bool = False,
    compliance: bool = True,
    resilience: bool = True,
) -> ResultsDict:
    """Tests a function that verifies ECDSA signatures.

    It runs the function with a set of test vectors selected depending on the curve,
    hash function, and compliance and resilience options.

    The function to test must conform to the :protocol:`Verify` protocol.

    The documentation has a table describing the available sources of test vectors
    depending on the curve and hash function.

    Args:
        verify_function: The function to test, see :attr:`Verify`.
        curve: The elliptic curve to use.
        hash_function: The hash function to use.
        pubkey_encoding: A public key encoding accepted by the function.

    Keyword Args:
        pre_hashed: Whether the message should be hashed before passing it to
            :attr:`verify_function`.
        compliance: Whether to use compliance test vectors.
        resilience: Whether to use resilience test vectors.

    Returns:
        A dictionary of results. Can contain the results of testing NIST (``nist``)
        and/or Wycheproof (``wycheproof``) test vectors, if there are any with the given
        parameters.

    Example:
        Let's test crypto-condor's internal verifier. First import the ECDSA module.

        >>> from crypto_condor.primitives import ECDSA

        We define the parameters we want to test (curve, hash, encoding).

        >>> curve = ECDSA.Curve.SECP256R1
        >>> hash_function = ECDSA.Hash.SHA_256
        >>> encoding = ECDSA.PubKeyEncoding.DER

        Then wrap the internal verifier to match the expected signature, defined by
        :protocol:`Verify`.

        >>> def my_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
        ...     return ECDSA._verify(public_key, hash_function, message, signature)

        And test this function.

        >>> group = ECDSA.test_verify(my_verify, curve, hash_function, encoding)
        [NIST] Verifying signatures ...

        >>> assert group["nist"].check()
        >>> assert group["wycheproof"].check()

    """
    rd = ResultsDict()

    if not compliance and not resilience:  # pragma: no cover (not interesting)
        logger.warning("No test vectors selected.")
        return rd

    if compliance:
        nist_results = _test_verify_nist(
            verify_function,
            curve,
            hash_function,
            pubkey_encoding,
            pre_hashed=pre_hashed,
        )
        if nist_results is not None:
            rd["nist"] = nist_results
    if resilience:
        wycheproof_results = _test_verify_wycheproof(
            verify_function,
            curve,
            hash_function,
            pubkey_encoding,
            pre_hashed=pre_hashed,
        )
        if wycheproof_results is not None:
            rd["wycheproof"] = wycheproof_results

    return rd


def _test_sign_nist(
    sign_function: Sign,
    curve: Curve,
    hash_function: Hash,
    key_encoding: KeyEncoding,
    *,
    pre_hashed: bool = False,
) -> Results | None:
    """Tests a signing function with NIST test vectors.

    Args:
        sign_function: The function to test, see :protocol:`Sign`.
        curve: The elliptic curve used.
        hash_function: The hash function used to generate the signatures.
        key_encoding: The key encoding accepted by the function.

    Keyword Args:
        pre_hashed: If True the messages are hashed before passing them to signing
            function.

    Returns:
        The results of signing messages and verifying the signatures with an internal
        implementation, or None if there are no test vectors for the given curve and
        hash function.
    """
    vectors = EcdsaSigGenVectors.load(curve, hash_function)
    if vectors.nist is None:
        return None

    results = Results(
        "ECDSA",
        "test_sign (NIST)",
        "Runs NIST test vectors on the signing function.",
        {
            "curve": curve,
            "hash_function": hash_function,
            "key_encoding": key_encoding,
        },
    )

    for test in track(vectors.nist.tests, "[NIST] Signing"):
        info = DebugInfo(test.id, TestType.VALID, ["Compliance"])
        try:
            match key_encoding:
                case KeyEncoding.DER:
                    k = ec.derive_private_key(
                        int(test.d, 16), curve.get_curve_instance()
                    )
                    key = k.private_bytes(
                        serialization.Encoding.DER,
                        serialization.PrivateFormat.PKCS8,
                        serialization.NoEncryption(),
                    )
                case KeyEncoding.PEM:
                    k = ec.derive_private_key(
                        int(test.d, 16), curve.get_curve_instance()
                    )
                    key = k.private_bytes(
                        serialization.Encoding.PEM,
                        serialization.PrivateFormat.PKCS8,
                        serialization.NoEncryption(),
                    )
                case KeyEncoding.INT:
                    key = bytes.fromhex(test.d)
        except (PubKeyImportError, ValueError):
            logger.debug("Test vector error", exc_info=True)
            continue

        raw_message = bytes.fromhex(test.message)
        if pre_hashed:
            digest = hashes.Hash(hash_function.get_hash_instance())
            digest.update(raw_message)
            message = digest.finalize()
        else:
            message = raw_message

        try:
            signature = sign_function(key, message)
        except Exception:
            logger.debug("Signing error", exc_info=True)
            info.error_msg = "Signing error"
            results.add(SigData(info, key, message, None))
            continue

        # Construct public key from Qx and Qy.
        if len(test.qx) % 2 == 1:
            qx = bytes.fromhex("0" + test.qx)
        else:
            qx = bytes.fromhex(test.qx)
        if len(test.qy) % 2 == 1:
            qy = bytes.fromhex("0" + test.qy)
        else:
            qy = bytes.fromhex(test.qy)
        encoded_point = b"\x04" + qx + qy
        pub_key = ec.EllipticCurvePublicKey.from_encoded_point(
            curve.get_curve_instance(), encoded_point
        )
        serialized_pub_key = pub_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        data = SigData(info, key, message, signature)
        if _verify(serialized_pub_key, hash_function, raw_message, signature):
            info.result = True
        else:
            info.error_msg = "Signature is not valid"
        results.add(data)

    return results


def test_sign(
    sign_function: Sign,
    curve: Curve,
    hash_function: Hash,
    key_encoding: KeyEncoding,
    *,
    pre_hashed: bool = False,
    compliance: bool = True,
) -> Results | None:
    """Tests a function that signs with ECDSA.

    It runs the function with a set of test vectors selected depending on the curve,
    hash function, and compliance option.

    The function to test must conform to the :protocol:`Sign` protocol.

    The documentation has a table describing the available sources of test vectors
    depending on the curve and hash function.

    Args:
        sign_function: The function to test, see :protocol:`Sign`.
        curve: The elliptic curve to use.
        hash_function: The hash function to use.
        key_encoding: The key encoding accepted by the signing function.

    Keyword Args:
        pre_hashed: If True, the messages are hashed before passing them to the signing
            function.
        compliance: Whether to use compliance test vectors.

    Returns:
        The results of testing with NIST test vectors if there are test vectors for the
        given curve and hash function.

    Example:
        Let's test crypto-condor's internal signing function. First, import the ECDSA
        module.

        >>> from crypto_condor.primitives import ECDSA

        We define the parameters we want to test (curve, hash, encoding).

        >>> curve = ECDSA.Curve.SECP256R1
        >>> hash_function = ECDSA.Hash.SHA_256
        >>> encoding = ECDSA.KeyEncoding.DER

        Then wrap the function to match the expected signature, defined by
        :protocol:`Sign`.

        >>> def my_sign(private_key: bytes, message: bytes) -> bytes:
        ...     return ECDSA._sign(private_key, hash_function, message)

        And test the function.

        >>> results = ECDSA.test_sign(my_sign, curve, hash_function, encoding)
        [NIST] Signing ...
        >>> assert results.check()
    """
    if compliance:
        return _test_sign_nist(
            sign_function, curve, hash_function, key_encoding, pre_hashed=pre_hashed
        )
    else:  # pragma: no cover (not interesting)
        logger.warning("No test vectors selected.")
        return None


def test_sign_then_verify(
    sign: Sign,
    verify: Verify,
    curve: Curve,
    key_encoding: KeyEncoding,
    pubkey_encoding: PubKeyEncoding,
    hash_function: Hash | None = None,
) -> Results:
    """Tests both functions.

    A single random key is generated and encoded. Random messages are generated, signed
    with the :attr:`sign` function, and the signatures verifies with the :attr:`verify`
    function. A test is passed is the signing function correctly generated a signature
    and the verifying function considers this signature valid.

    Args:
        sign: The signing function to test.
        verify: The verifying function to test.
        curve: The elliptic curve to use.
        key_encoding: The private key encoding used by the signing function.
        pubkey_encoding: The public key encoding used by the verifying function.
        hash_function: Optional. The given hash function is used to hash the message
            before passing it to the functions. If None, the message is passed as is.

    Returns:
        The results. A test is considered a pass if the produced signature is valid for
        the corresponding message according to the verifying function.

    Example:
        Let's test crypto-condor's internal functions. First import the ECDSA module.

        >>> from crypto_condor.primitives import ECDSA

        Define the test parameters.

        >>> curve = ECDSA.Curve.SECP256R1
        >>> key_encoding = ECDSA.KeyEncoding.DER
        >>> pubkey_encoding = ECDSA.PubKeyEncoding.DER

        Wrap both functions to match the corresponding protocols (:protocol:`Verify` and
        :protocol:`Sign`).

        >>> def my_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
        ...     return ECDSA._verify(public_key, hash_function, message, signature)
        >>> def my_sign(private_key: bytes, message: bytes) -> bytes:
        ...     return ECDSA._sign(private_key, hash_function, message)

        Then test both functions.

        >>> results = ECDSA.test_sign_then_verify(my_sign, my_verify, curve, key_encoding, pubkey_encoding)
        Signing and verifying ...
        >>> assert results.check()
    """  # noqa: E501
    results = Results(
        "ECDSA",
        "test_sign_then_verify",
        "Tests both functions consecutively with randomly generated values.",
        {
            "curve": curve,
            "key_encoding": key_encoding,
            "pubkey_encoding": pubkey_encoding,
            "hash_function": hash_function,
        },
    )
    results.add_notes({"Random test": "Test values are randomly generated."})

    # Generate a fixed key.
    key = ec.generate_private_key(curve.get_curve_instance())
    match key_encoding:
        case KeyEncoding.PEM:
            encoded_key = key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        case KeyEncoding.DER:
            encoded_key = key.private_bytes(
                serialization.Encoding.DER,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        case KeyEncoding.INT:
            d = key.private_numbers().private_value
            encoded_key = d.to_bytes((d.bit_length() + 7) // 8, "big")

    # Derive serialized public key to verify the signature.
    pub_key = key.public_key()
    match pubkey_encoding:
        case PubKeyEncoding.PEM:
            encoded_pubkey = pub_key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        case PubKeyEncoding.DER:
            encoded_pubkey = pub_key.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        case PubKeyEncoding.UNCOMPRESSED:
            qx = hex(pub_key.public_numbers().x)
            if len(qx) % 2 == 1:
                qx = "0" + qx
            qy = hex(pub_key.public_numbers().y)
            if len(qy) % 2 == 1:
                qy = "0" + qy
            encoded_pubkey = bytes.fromhex(f"04{qx}{qy}")

    for tid in track(range(1000), "Signing and verifying"):
        info = DebugInfo(tid, TestType.VALID, ["RandomTest"])
        message = random.randbytes(512 + tid)
        if hash_function:
            digest = hashes.Hash(hash_function.get_hash_instance())
            digest.update(message)
            message = digest.finalize()

        try:
            signature = sign(encoded_key, message)
        except Exception:
            info.error_msg = "Signing failed"
            logger.debug("Error running sign function", exc_info=True)
            results.add(SigData(info, encoded_key, message, None))
            continue

        data = SigData(info, encoded_pubkey, message, signature)
        try:
            res = verify(encoded_pubkey, message, signature)
        except Exception:
            info.error_msg = "Signature verification failed"
            logger.debug("Error running verify function", exc_info=True)
            results.add(data)
            continue

        if res:
            info.result = True
        else:
            info.error_msg = "Signature is not valid or verification is incorrect"
        results.add(data)

    return results


# TODO: accept DER- or PEM-encoded keys?
def test_key_pair_gen(keygen: KeyGen, curve: Curve) -> ResultsDict:
    """Tests a function that generates ECDSA key pairs.

    It uses the given function to generate 5000 keys pairs, in the format defined by
    :attr:`KeyPair`. The private value is used to derive a private key. If the
    coordinates of the public value are included it checks that these represent the
    correct public key. A test passes if the private value could be used to derive the
    private key and if the public value matches, if applicable.

    A second test is performed, which consists in concatenating the private values in a
    single stream, and testing it with :mod:`~crypto_condor.primitives.TestU01`.

    Args:
        keygen: The function that generates ECDSA key pairs. See :protocol:`KeyGen` for
            the expected signature of this function.
        curve: The elliptic curve to use.

    Returns:
        A dictionary of results containing the results of generating the key pairs
        (``keygen``) and the result of testing the private values with TestU01
        (``testu01``).

    Notes:
        5000 keys gives us at least 1 million bits on ``secp224r1``.

    Example:
        Let's test PyCryptodome's key generation. We import the ECDSA module.

        >>> from crypto_condor.primitives import ECDSA

        We pick the curve secp224r1.

        >>> curve = ECDSA.Curve.SECP224R1

        Then wrap the implementation to match the signature defined by
        :protocol:`KeyGen`.

        >>> from Crypto.PublicKey import ECC
        >>> def my_key_gen() -> tuple[int, int|None, int|None]:
        ...     key = ECC.generate(curve=str(curve))
        ...     return (int(key.d), key.pointQ.x, key.pointQ.y)

        And test it.

        >>> results_dict = ECDSA.test_key_pair_gen(my_key_gen, curve)
        Generating keys ...
        >>> assert results_dict["keygen"].check()
        >>> assert results_dict["testu01"].check()  # doctest: +SKIP
    """
    results_dict = ResultsDict()

    keygen_results = Results(
        "ECDSA", "test_key_pair_gen", "Tests key pair generation", {"curve": curve}
    )

    keys = b""

    ec_curve = curve.get_curve_instance()

    for tid in track(range(5000), "Generating keys"):
        info = DebugInfo(tid, TestType.VALID, ["RandomTest"])
        try:
            t = keygen()
            d, qx, qy = t
        except Exception as error:
            info.error_msg = f"Key generation failed: {str(error)}"
            logger.debug("Error running key generation", exc_info=True)
            keygen_results.add(KeyGenData(info, None, None, None))
            continue

        data = KeyGenData(info, d, qx, qy)

        try:
            private_key = ec.derive_private_key(d, ec_curve)
        except (TypeError, ValueError) as error:
            info.error_msg = (
                f"Failed to derive private key from private value: {str(error)}"
            )
            keygen_results.add(data)
            continue

        # If keygen returns *both* public coordinates, then compare them to the ones
        # from the derived public key.
        # This concludes the keygen test so if there are no problems we add a passed
        # result.
        if qx is None and qy is None:
            info.result = True
        else:
            public_key = private_key.public_key()
            public_numbers = public_key.public_numbers()
            # Be specific about which coordinate is incorrect.
            if qx != public_numbers.x and qy != public_numbers.y:
                info.error_msg = "Wrong public coordinates"
            elif qx != public_numbers.x:
                info.error_msg = "Wrong public x-coordinate"
            elif qy != public_numbers.y:
                info.error_msg = "Wrong public y-coordinate"
            else:
                info.result = True

        keygen_results.add(data)

        match curve:
            case Curve.SECP521R1:
                # Remove leading byte if equal to 0x01
                h = hex(d)[2:]
                if len(h) % 2 == 1:
                    if h[0] == "1":
                        h = h[1:]
                        keys += bytes.fromhex(h)
                    else:
                        keys += d.to_bytes((d.bit_length() + 7) // 8, "big")
            case Curve.SECT283R1 | Curve.SECT409R1 | Curve.SECT571R1:
                # Remove leading byte if less than 0x10
                h = hex(d)[2:]
                if len(h) % 2 == 1:
                    h = h[1:]
                keys += bytes.fromhex(h)
            case _:
                keys += d.to_bytes((d.bit_length() + 7) // 8, "big")

    results_dict["keygen"] = keygen_results

    with tempfile.NamedTemporaryFile("wb") as fp:
        fp.write(keys)
        testu01_result = TestU01.test_file(fp.name)

    if testu01_result is not None:
        results_dict["testu01"] = testu01_result
    return results_dict


# --------------------------- Runners -------------------------------------------------


def _run_python(
    curve: Curve,
    hash_function: Hash,
    pre_hashed: bool,
    run_test_sign: bool,
    key_encoding: KeyEncoding | None,
    run_test_verify: bool,
    pubkey_encoding: PubKeyEncoding | None,
    run_test_sign_then_verify: bool,
    compliance: bool,
    resilience: bool,
) -> ResultsDict:
    """Runs a Python wrapper.

    Args:
        curve: The elliptic curve to test.
        hash_function: The hash function to test.
        pre_hashed: Whether the message should be hashed before being passed to the
            wrapper.
        run_test_sign: Whether to test the signing function.
        key_encoding: The private key encoding used by the signing function. Set to None
            only when not testing the signing function.
        run_test_verify: Whether to test the signature verification function.
        pubkey_encoding: The public key encoding used by the verifying function. Set to
            None only when not testing the verifying function.
        run_test_sign_then_verify: If True, both functions are tested by generating a
            random key and random messages, signing them, and verifying the signature.
        compliance: Whether to use compliance test vectors.
        resilience: Whether to use resilience test vectors.

    Returns:
        A dictionary of results. Depending on the options used and test vectors
        available, it contains results of testing the signing function ("sign"), testing
        the verifying function ("verify-nist" and "verify-wycheproof"), and testing both
        ("sign-then-verify").
    """
    wrapper = Path.cwd() / "ecdsa_wrapper.py"
    if not wrapper.is_file():
        raise FileNotFoundError("Can't find ecdsa_wrapper.py")

    logger.info("Loading Python wrapper")

    # Add CWD to the path, at the beginning in case this is called more than once, since
    # the previous CWD would have priority.
    sys.path.insert(0, str(Path.cwd()))

    # Before importing the wrapper we check if it's already in the loaded modules, in
    # which case we want to reload it or we would be testing the wrapper loaded
    # previously.
    imported = "ecdsa_wrapper" in sys.modules.keys()

    # Import it normally.
    try:
        ecdsa_wrapper = importlib.import_module("ecdsa_wrapper")
    except ModuleNotFoundError as error:
        logger.debug(error)
        raise FileNotFoundError("Can't load the wrapper!") from error

    # Then reload it if necessary.
    if imported:
        logger.debug("Reloading the ECDSA Python wrapper")
        ecdsa_wrapper = importlib.reload(ecdsa_wrapper)

    logger.info("Python wrapper loaded")

    results_dict = ResultsDict()

    if run_test_sign:
        if key_encoding is None:
            raise ValueError(
                "key_encoding is required when testing the signing function"
            )
        logger.info("Testing signing function")
        sign_result = test_sign(
            ecdsa_wrapper.sign,
            curve,
            hash_function,
            key_encoding,
            pre_hashed=pre_hashed,
            compliance=compliance,
        )
        if sign_result is not None:
            results_dict["nist"] = sign_result

    if run_test_verify:
        if pubkey_encoding is None:
            raise ValueError(
                "pubkey_encoding is required when testing the verifying function"
            )
        logger.info("Testing verify function")
        verify_result = test_verify(
            ecdsa_wrapper.verify,
            curve,
            hash_function,
            pubkey_encoding,
            pre_hashed=pre_hashed,
            compliance=compliance,
            resilience=resilience,
        )
        if verify_result is not None:
            if verify_result.get("nist", None) is not None:
                results_dict["nist/verify"] = verify_result["nist"]
            if verify_result.get("wycheproof", None) is not None:
                results_dict["wycheproof/verify"] = verify_result["wycheproof"]

    if run_test_sign_then_verify:
        if key_encoding is None:
            raise ValueError(
                "key_encoding is required when testing the signing function"
            )
        if pubkey_encoding is None:
            raise ValueError(
                "pubkey_encoding is required when testing the verifying function"
            )
        logger.info("Testing sign then verify")
        stv_result = test_sign_then_verify(
            ecdsa_wrapper.sign,
            ecdsa_wrapper.verify,
            curve,
            key_encoding,
            pubkey_encoding,
            hash_function,
        )
        if stv_result is not None:
            results_dict["sign-then-verify"] = stv_result

    # To de-clutter the path, remove the CWD.
    sys.path.remove(str(Path.cwd()))

    return results_dict


def run_wrapper(
    language: Wrapper,
    curve: Curve,
    hash_function: Hash,
    pre_hashed: bool,
    test_sign: bool,
    key_encoding: KeyEncoding | None,
    test_verify: bool,
    pubkey_encoding: PubKeyEncoding | None,
    test_sign_then_verify: bool,
    compliance: bool,
    resilience: bool,
) -> ResultsDict:
    """Runs a wrapper.

    Args:
        language: The language of the wrapper.
        curve: The elliptic curve to use.
        hash_function: The hash function to use.
        pre_hashed: Whether the message passed should be hashed beforehand.
        test_sign: Whether to test the signing function.
        key_encoding: The private key encoding used by the signing function. Set to None
            only when not testing the signing function.
        test_verify: Whether to test the signature verification function.
        pubkey_encoding: The public key encoding used by the verifying function. Set to
            None only when not testing the verifying function.
        test_sign_then_verify: If True, both functions are tested by generating a random
            key and random messages, signing them, and verifying the signature.
        compliance: Whether to use compliance test vectors.
        resilience: Whether to use resilience test vectors.

    Returns:
        A dictionary of results. Depending on the options used and test vectors
        available, it contains results of testing the signing function (``sign``),
        testing the verifying function (``nist/verify`` and ``wycheproof/verify``), and
        testing both (``sign-then-verify``).
    """
    match language:
        case Wrapper.PYTHON:
            return _run_python(
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
        case _:  # pragma: no cover (mypy)
            raise ValueError("Unsupported language %s" % str(language))
