"""Module for RSAES."""

import inspect
import logging
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
    _load_python_harness,
)
from crypto_condor.vectors.RSAES import Hash, RsaDecVectors, Scheme

# -------------------------------------------------------------------------------------
# Module
# -------------------------------------------------------------------------------------

logger = logging.getLogger(__name__)


def __dir__():  # pragma: no cover
    return [
        # Enums
        Wrapper.__name__,
        # Protocols
        DecryptPkcs.__name__,
        DecryptOaep.__name__,
        # Dataclasses
        # Functions
        test_decrypt_pkcs.__name__,
        test_decrypt_oaep.__name__,
        # Harnesses
        test_harness_python.__name__,
        # Imported
        Scheme.__name__,
        Hash.__name__,
    ]


# -------------------------------------------------------------------------------------
# Enums
# -------------------------------------------------------------------------------------


class Wrapper(strenum.StrEnum):
    """Available wrappers."""

    PYTHON = "Python"


# -------------------------------------------------------------------------------------
# Protocols
# -------------------------------------------------------------------------------------


class DecryptPkcs(Protocol):
    """Represents a function that decrypts messages encrypted with RSASSA-PKCS1-v1_5."""

    def __call__(self, private_key: bytes, ciphertext: bytes) -> bytes:
        """Decrypts a message encrypted with RSA.

        Args:
            private_key: The private part of the key used to encrypt, in PEM format.
            ciphertext: The ciphertext to decrypt.

        Returns:
            The plaintext.
        """
        ...  # pragma: no cover (protocol)


class DecryptOaep(Protocol):
    """Represents a function that decrypts messages encrypted with RSAES-OAEP."""

    def __call__(self, private_key: bytes, ciphertext: bytes, label: bytes) -> bytes:
        """Decrypts a message encrypted with RSA.

        Args:
            private_key: The private part of the key used to encrypt, in PEM format.
            ciphertext: The ciphertext to decrypt.
            label: The optional label, can be an empty byte-array (b"").

        Returns:
            The plaintext.
        """
        ...  # pragma: no cover (protocol)


# -------------------------------------------------------------------------------------
# Data classes
# -------------------------------------------------------------------------------------


@attrs.define
class DecryptData:
    """Class for storing decrypt debug data.

    Args:
        info: Common debug info, see :class:`crypto_condor.primitives.common.DebugInfo`.
        key: The key in PEM format.
        ciphertext: The ciphertext to decrypt.
        plaintext: The expected plaintext.
        result: The resulting plaintext.
        label: (RSAES-OAEP only) The optional label.
    """

    info: DebugInfo
    key: bytes
    ciphertext: bytes
    plaintext: bytes
    result: bytes | None
    label: bytes | None = None

    def __str__(self) -> str:
        """Returns a human-friendly representation."""
        s = str(self.info)
        s += f"""key = {self.key.decode()}
ciphertext = {self.ciphertext.hex()}
expected plaintext = {self.plaintext.hex()}
result = {self.result.hex() if self.result else "<empty>"}
"""
        if self.label is not None:
            s += f"label = {self.label.hex() if self.label else '<empty>'}\n"
        return s


# -------------------------------------------------------------------------------------
# Test functions
# -------------------------------------------------------------------------------------


def test_decrypt_pkcs(decrypt_function: DecryptPkcs) -> ResultsDict:
    """Tests a function that decrypts RSAES-PKCS1-v1_5 ciphertexts.

    Only Wycheproof vectors are available.

    Args:
        decrypt_function: The function to test.

    Returns:
        A dictionary of results, one for each test vectors file. The keys are
        "Wycheproof/decrypt/{filename}".
    """
    results_dict = ResultsDict()
    vectors = RsaDecVectors.load(Scheme.PKCS)
    if vectors.wycheproof is None:
        return results_dict

    for filename, vectors_file in track(
        vectors.wycheproof.items(),
        "[Wycheproof] Decrypting RSAES-PKCS1-v1_5 ciphertexts",
    ):
        results = Results(
            "RSA",
            "test_decrypt (RSAES-PKCS1-v1_5)",
            "Tests a functions that decrypts RSAES-PKCS1-v1_5 ciphertexts.",
            {},
        )
        results_dict[f"Wycheproof/decrypt/{filename}"] = results
        logger.debug("Using vectors from: %s" % filename)
        # Add Wycheproof notes to results.
        results.notes |= vectors_file.get("notes", {})
        for group in vectors_file["testGroups"]:
            pem = group["privateKeyPem"]
            key = pem.encode()
            for test in group["tests"]:
                test_type = TestType(test["result"])
                info = DebugInfo(
                    test["tcId"], test_type, test["flags"], comment=test["comment"]
                )
                msg = bytes.fromhex(test["msg"])
                ct = bytes.fromhex(test["ct"])
                try:
                    pt = decrypt_function(key, ct)
                except Exception as error:
                    if test_type == TestType.INVALID:
                        info.result = True
                    else:
                        info.error_msg = f"Error running decrypt function: {str(error)}"
                        logger.debug("Error running decrypt function", exc_info=True)
                    results.add(DecryptData(info, key, ct, msg, None))
                    continue
                res = pt == msg
                match (test_type, res):
                    case (TestType.VALID, True) | (TestType.INVALID, False):
                        info.result = True
                    case (TestType.VALID, False):
                        info.error_msg = "Wrong plaintext"
                    case (TestType.INVALID, True):
                        info.error_msg = "Invalid ciphertext decrypted"
                    case (TestType.ACCEPTABLE, (True | False)):
                        info.result = res
                results.add(DecryptData(info, key, ct, msg, pt))

    return results_dict


def test_decrypt_oaep(
    decrypt_function: DecryptOaep, hash_algorithm: Hash, mgf_hash: Hash | None = None
) -> ResultsDict:
    """Tests a function that decrypts RSAES-OAEP ciphertexts.

    Only Wycheproof vectors are available.

    Args:
        decrypt_function: The function to test.
        hash_algorithm: The hash algorithm used to generate the ciphertexts.
        mgf_hash: The hash algorithm used with MGF1. If None, the same as
            :attr:`hash_algorithm` is used.

    Returns:
        A dictionary of results, one for each test vectors file. The keys are
        "Wycheproof/decrypt/{filename}".
    """
    results_dict = ResultsDict()
    vectors = RsaDecVectors.load(Scheme.OAEP, hash_algorithm, mgf_hash)
    if vectors.wycheproof is None:
        return results_dict
    for filename, vectors_file in track(
        vectors.wycheproof.items(),
        "[Wycheproof] Decrypting RSAES-OAEP ciphertexts",
    ):
        results = Results(
            "RSA",
            "test_decrypt (RSAES-OAEP)",
            "Tests a functions that decrypts RSAES-OAEP ciphertexts.",
            {"hash_algorithm": hash_algorithm, "mgf_hash": mgf_hash},
        )
        results_dict[f"Wycheproof/decrypt/{filename}"] = results
        logger.debug("Using vectors from: %s" % filename)
        # Add Wycheproof notes to results.
        results.notes |= vectors_file.get("notes", {})
        for group in vectors_file["testGroups"]:
            pem = group["privateKeyPem"]
            key = pem.encode()
            for test in group["tests"]:
                test_type = TestType(test["result"])
                info = DebugInfo(
                    test["tcId"], test_type, test["flags"], comment=test["comment"]
                )
                msg = bytes.fromhex(test["msg"])
                ct = bytes.fromhex(test["ct"])
                label = bytes.fromhex(test["label"])
                try:
                    pt = decrypt_function(key, ct, label)
                except Exception as error:
                    if test_type == TestType.INVALID:
                        info.result = True
                    else:
                        info.error_msg = f"Error running decrypt function: {str(error)}"
                        logger.debug("Error running decrypt function", exc_info=True)
                    results.add(DecryptData(info, key, ct, msg, None))
                    continue
                res = pt == msg
                match (test_type, res):
                    case (TestType.VALID, True) | (TestType.INVALID, False):
                        info.result = True
                    case (TestType.VALID, False):
                        info.error_msg = "Wrong plaintext"
                    case (TestType.INVALID, True):
                        info.error_msg = "Invalid ciphertext decrypted"
                    case (TestType.ACCEPTABLE, (True | False)):
                        info.result = res
                results.add(DecryptData(info, key, ct, msg, pt, label))

    return results_dict


# -------------------------------------------------------------------------------------
# Harness parsers
# -------------------------------------------------------------------------------------


@attrs.define
class OaepOpts:
    """RSAES-OAEP options."""

    algo: Hash
    mgf_algo: Hash | None

    @classmethod
    def parse(cls, opts: list[str]):
        """Parses options from the name of a harness function."""
        if len(opts) not in {1, 2}:
            logger.error(
                "Invalid number of options, got %d, expected 1 or 2", len(opts)
            )
            return None
        try:
            algo = Hash.from_name(opts[0])
        except ValueError as error:
            logger.error("Invalid hash function: %s", str(error))
            return None

        if len(opts) == 1:
            return cls(algo, None)

        try:
            mgf_algo = Hash.from_name(opts[1])
        except ValueError as error:
            logger.error("Invalid hash function: %s", str(error))
            return None

        return cls(algo, mgf_algo)


# -------------------------------------------------------------------------------------
# Python harness
# -------------------------------------------------------------------------------------


def test_harness_python(
    harness: Path, compliance: bool, resilience: bool
) -> ResultsDict:
    """Tests a Python harness.

    Args:
        harness:
            Path to the harness.
        compliance:
            Whether to use compliance test vectors.
        resilience:
            Whether to use resilience test vectors.

    Returns:
        A dictionary of results.
    """
    results = ResultsDict()
    rsa_harness = _load_python_harness(harness)
    if rsa_harness is None:
        return results

    for name, func in inspect.getmembers(rsa_harness, inspect.isfunction):
        if not name.startswith("CC_RSAES_"):
            continue
        logger.info("Harness function found: %s", name)

        match name.split("_")[2:]:
            case ["encrypt", *_]:
                pass
            case ["decrypt", "pkcs"]:
                results |= test_decrypt_pkcs(func)
            case ["decrypt", "oaep", *opts]:
                if (parsed := OaepOpts.parse(opts)) is None:
                    continue
                results |= test_decrypt_oaep(func, parsed.algo, parsed.mgf_algo)
            case [op, *_]:
                logger.error(
                    "Invalid operation %s for RSA harness, skipped %s", op, name
                )
                continue

    return results
