"""Module for Ed25519."""

import inspect
import json
import logging
from importlib import resources
from pathlib import Path
from typing import Protocol

import attrs
import strenum
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from rich.progress import track

from crypto_condor.primitives.common import (
    Results,
    ResultsDict,
    TestInfo,
    TestType,
    _load_python_harness,
)
from crypto_condor.vectors._ed25519.ed25519_pb2 import Ed25519Test, Ed25519Vectors

# -------------------------------------------------------------------------------------
# Module
# -------------------------------------------------------------------------------------

logger = logging.getLogger(__name__)


def __dir__():  # pragma: no cover
    return [
        # Enums
        Wrapper.__name__,
        # Protocols
        Sign.__name__,
        # Test functions
        test_sign.__name__,
        test_verify.__name__,
        test_output_sign.__name__,
        # Runners
        test_harness.__name__,
        test_harness_python.__name__,
    ]


# -------------------------------------------------------------------------------------
# Enums
# -------------------------------------------------------------------------------------


class Wrapper(strenum.StrEnum):
    """Supported languages for wrappers."""

    PYTHON = "Python"


class Variant(strenum.StrEnum):
    """Ed25519 variants."""

    ED25519 = "Ed25519"
    """EdDSA instantiated over edwards25519."""
    ED25519PH = "Ed25519ph"
    """HashEdDSA instantiated over edwards25519."""
    ED25519CTX = "Ed25519ctx"
    """Ed25519 variant with context string."""


class Vectype(strenum.StrEnum):
    """Type of test vectors."""

    SIGN = "sign"
    VERIFY = "verify"


# -------------------------------------------------------------------------------------
# Vectors
# -------------------------------------------------------------------------------------


def _load_vectors(
    variant: Variant, vectype: Vectype, compliance: bool, resilience: bool
) -> list[Ed25519Vectors]:
    """Loads vectors for a given parameter set.

    Args:
        variant:
            The Ed25519 variant to use.
        vectype:
            The type of test vectors to load.
        compliance:
            Whether to load compliance test vectors.
        resilience:
            Whether to load resilience test vectors.

    Returns:
        A list of vectors.
    """
    vectors: list[Ed25519Vectors] = list()
    vectors_dir = resources.files("crypto_condor") / "vectors/_ed25519"

    sources_file = vectors_dir / "ed25519.json"
    with sources_file.open("r") as file:
        sources = json.load(file)

    for filename in sources.get(str(variant)):
        vectors_file = vectors_dir / "pb2" / filename
        _vec = Ed25519Vectors()
        logger.debug("Loading Ed25519 vectors from %s", filename)
        try:
            _vec.ParseFromString(vectors_file.read_bytes())
        except Exception:
            logger.exception("Failed to load Ed25519 vectors from file %s", filename)
            continue
        if vectype == "sign" and not _vec.sign:
            continue
        if vectype == "verify" and not _vec.verify:
            continue
        if _vec.compliance and compliance:
            vectors.append(_vec)
        if not _vec.compliance and resilience:
            vectors.append(_vec)

    if not vectors:
        logger.error(
            "No Ed25519 test vectors loaded for variant=%s, vectype=%s, compliance=%s, resilience=%s",  # noqa: E501
            str(variant),
            str(vectype),
            compliance,
            resilience,
        )

    return vectors


# -------------------------------------------------------------------------------------
# Protocols
# -------------------------------------------------------------------------------------


class Sign(Protocol):
    """Represents a function that signs with Ed25519."""

    def __call__(self, sk: bytes, msg: bytes) -> bytes:  # pragma: no cover
        """Signs a message with Ed25519.

        Args:
            sk:
                The raw private key.
            msg:
                The message to sign.

        Returns:
            The Ed25519 signature.
        """
        ...


class Verify(Protocol):
    """Represents a function that verifies Ed25519 signatures."""

    def __call__(self, pk: bytes, msg: bytes, sig: bytes) -> bool:  # pragma: no cover
        """Verifies an Ed25519 signature.

        Args:
            pk:
                The raw 32-byte public key.
            msg:
                The data that was signed.
            sig:
                The signature to verify.

        Returns:
            True if the signature is valid, False otherwise.
        """
        ...


# -------------------------------------------------------------------------------------
# Dataclasses
# -------------------------------------------------------------------------------------


@attrs.define
class SignData:
    """Debug data for `test_sign_ed25519`."""

    sk: bytes
    msg: bytes
    sig: bytes
    ret_sig: bytes | None = None

    def __str__(self):
        """Returns a string representation."""
        return f"""sk = {self.sk.hex()}
msg = {self.msg.hex()}
sig = {self.sig.hex()}
returned_sig = {self.ret_sig.hex() if self.ret_sig else "<none>"}
"""

    @classmethod
    def from_test(cls, test: Ed25519Test):
        """Returns a new instance from a test."""
        return cls(test.sk, test.msg, test.sig)


@attrs.define
class VerifyData:
    """Debug data for `test_verify_ed25519`."""

    pk: bytes
    msg: bytes
    sig: bytes
    ret: bool | None = None

    def __str__(self):
        """Returns a string representation."""
        return f"""pk = {self.pk.hex()}
msg = {self.msg.hex()}
sig = {self.sig.hex()}
result = {self.ret}
"""

    @classmethod
    def from_test(cls, test: Ed25519Test):
        """Returns a new instance from a test."""
        return cls(test.pk, test.msg, test.sig)


# -------------------------------------------------------------------------------------
# Test functions
# -------------------------------------------------------------------------------------


def test_sign(
    sign: Sign, compliance: bool = True, resilience: bool = True
) -> ResultsDict:
    """Tests a function that generates signatures with Ed25519.

    Calls the `sign` function on valid keys and messages to generate signatures. The
    signatures are compared to the test vector values. The test passes if all signatures
    are correct.

    Args:
        sign:
            The function to test. Must follow :protocol:`Sign`.
        compliance:
            If True, compliance test vectors are used if available.
        resilience:
            If True, resilience test vectors are used if available.

    Returns:
        An instance of :class:`ResultsDict`, with one :class:`Results` per test vectors
        file used.
    """
    rd = ResultsDict()

    test_vectors = _load_vectors(Variant.ED25519, Vectype.SIGN, compliance, resilience)
    if not test_vectors:
        return rd

    test: Ed25519Test
    for vectors in test_vectors:
        results = Results.new("Test Ed25519 signing", [], vectors)
        rd.add(results, extra_values=[vectors.source])

        for test in track(
            vectors.tests, rf"\[Ed25519]\[{vectors.source}] Testing signing"
        ):
            data = SignData.from_test(test)
            info = TestInfo.new_from_test(test, vectors.compliance, data)

            try:
                data.ret_sig = sign(test.sk, test.msg)
            except NotImplementedError:
                logger.warning("Ed25519 sign not implemented, test skipped")
                return rd
            except Exception as error:
                logger.debug("Caught exception from Ed25519 sign", exc_info=True)
                info.fail(f"Exception raised: {str(error)}")
                results.add(info)
                continue

            match (test.type, data.ret_sig == data.sig):
                case (TestType.VALID, True):
                    info.ok()
                case (TestType.VALID, False):
                    info.fail("Wrong signature")
                case _:
                    # We currently have only valid test vectors.
                    logger.error("Invalid test type %s", str(test.type))
                    continue
            results.add(info)

    return rd


def test_verify(
    verify: Verify, compliance: bool = True, resilience: bool = True
) -> ResultsDict:
    """Tests a function that verifies Ed25519 signatures.

    Calls the `verify` function to verify Ed25519 signatures. Keys and messages are
    valid values. There are valid and invalid signatures: the test passes if the
    implementation correctly verifies all valid signatures and rejects all invalid
    signatures.

    Args:
        verify:
            The function to test. Must follow :protocol:`Verify`.
        compliance:
            If True, compliance test vectors are used if available.
        resilience:
            If True, resilience test vectors are used if available.

    Returns:
        An instance of :class:`ResultsDict`, with one :class:`Results` per test vectors
        file used.
    """
    rd = ResultsDict()

    test_vectors = _load_vectors(
        Variant.ED25519, Vectype.VERIFY, compliance, resilience
    )
    if not test_vectors:
        return rd

    for vectors in test_vectors:
        results = Results.new("Test Ed25519 verifying", [], vectors)
        rd.add(results, extra_values=[vectors.source])

        for test in track(
            vectors.tests, rf"\[Ed25519]\[{vectors.source}] Testing verifying"
        ):
            data = VerifyData.from_test(test)
            info = TestInfo.new_from_test(test, vectors.compliance, data)

            try:
                data.ret = verify(test.pk, test.msg, test.sig)
            except NotImplementedError:
                logger.warning("Ed25519 verify not implemented, test skipped")
                return rd
            except Exception as error:
                logger.debug("Caught exception from Ed25519 verify", exc_info=True)
                info.fail(f"Exception raised: {str(error)}")
                results.add(info)
                continue

            # NOTE: RFC 8032 does not contain invalid test vectors but Wycheproof does.
            # Most flags are related to actual bugs so they should be rejected. However
            # a couple of flags are marked as CAN_OF_WORMS, which are related to small
            # bugs that may lead to a vulnerability in combination with other factors.
            # For now, we consider that all invalid test vectors must be rejected.
            match (test.type, data.ret):
                case (TestType.VALID, True):
                    info.ok()
                case (TestType.VALID, False):
                    info.fail("Valid signature was rejected")
                case (TestType.INVALID, True):
                    info.fail("Invalid signature was accepted")
                case (TestType.INVALID, False):
                    info.ok()
                case (TestType.VALID | TestType.INVALID, _):
                    info.fail("Invalid return value, expected True or False")
                case _:  # pragma: no cover
                    # NOTE: there are no acceptable test vectors so this should not
                    # happen.
                    logger.error("Invalid test type %s", str(test.type))
                    continue
            results.add(info)

    return rd


def test_output_sign(output: Path) -> ResultsDict:
    """Tests the output of a function that signs with Ed25519.

    Signatures, with their corresponding signing key and data, are read from a file and
    verified using :mod:`cryptography`. The test passes if all signatures are valid.

    Format:

        - One line per signature operation.
        - All values are encoded in hexadecimal.
        - Values are separated by a single forward slash, no spaces.
        - Lines are separated by a single newline.
        - The order of arguments is:

            .. code::

                secret_key / message / signature

    Args:
        output:
            The path to the output file.

    Returns:
        A dictionary containing a single :class:`Results`.
    """
    rd = ResultsDict()
    res = Results.new(
        "Tests the output of a function that signs with Ed25519", ["output"]
    )
    rd.add(res, ["output"])

    with output.open("r") as fp:
        lines = fp.readlines()

    for index, line in enumerate(lines, 1):
        if line.startswith("#"):
            continue
        line = line.strip()
        match line.split("/"):
            case [_sk, _msg, _sig]:
                sk, msg, sig = map(bytes.fromhex, (_sk, _msg, _sig))
            case _:
                logger.error("Failed to parse line %d (expected 3 values)", index)
                continue

        info = TestInfo.new(index, TestType.VALID, ["UserInput"])
        try:
            key = Ed25519PrivateKey.from_private_bytes(sk)
            pk = key.public_key()
            _ = pk.verify(sig, msg)
        except InvalidSignature:
            info.fail("Invalid signature")
        except Exception as error:
            logger.exception("Failed to test signature")
            info.fail(f"Failed to test signature: {error}")
        else:
            info.ok()
        finally:
            res.add(info)

    return rd


# -------------------------------------------------------------------------------------
# Harnesses
# -------------------------------------------------------------------------------------


def test_harness_python(
    harness: Path, compliance: bool, resilience: bool
) -> ResultsDict:
    """Tests an Ed25519 Python harness.

    Args:
        harness:
            A path to the harness to test.
        compliance:
            Whether to use compliance test vectors.
        resilience:
            Whether to use resilience test vectors.
    """
    ed25519_harness = _load_python_harness(harness)

    rd = ResultsDict()

    for funcname, _ in inspect.getmembers(ed25519_harness, inspect.isfunction):
        func = getattr(ed25519_harness, funcname)
        match funcname.split("_"):
            case ["CC", "ed25519", "sign"]:
                rd |= test_sign(func, compliance, resilience)
            case ["CC", "ed25519", "verify"]:
                rd |= test_verify(func, compliance, resilience)
            case ["CC", "ed25519", *_]:
                logger.error("Invalid CC_ed25519 function %s", funcname)
                continue

    return rd


def test_harness(harness: Path, compliance: bool, resilience: bool) -> ResultsDict:
    """Tests an Ed25519 harness.

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
            return test_harness_python(harness, compliance, resilience)
        case _:
            raise ValueError(f"No test for '{harness.suffix}' harnesss")
