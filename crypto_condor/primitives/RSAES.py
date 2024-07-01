"""Module for RSAES."""

import importlib
import logging
import sys
from pathlib import Path
from typing import Protocol

import attrs
import strenum
from rich.progress import track

from crypto_condor.primitives.common import DebugInfo, Results, ResultsDict, TestType
from crypto_condor.vectors.RSAES import Hash, RsaDecVectors, Scheme

# --------------------------- Module --------------------------------------------------
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
        run_rsaes_wrapper.__name__,
        # Imported
        Scheme.__name__,
        Hash.__name__,
    ]


# --------------------------- Enums ---------------------------------------------------


class Wrapper(strenum.StrEnum):
    """Available wrappers."""

    PYTHON = "Python"


# --------------------------- Protocols -----------------------------------------------


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


# --------------------------- Data classes --------------------------------------------
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
result = {self.result.hex() if self.result else '<empty>'}
"""
        if self.label is not None:
            s += f"label = {self.label.hex() if self.label else '<empty>'}\n"
        return s


# --------------------------- Test functions ------------------------------------------
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


# --------------------------- Runners -------------------------------------------------
def _run_rsaes_python_wrapper(
    scheme: Scheme, hash_algorithm: Hash | None, mgf_hash: Hash | None
) -> ResultsDict:
    """Runs the Python RSAES wrapper.

    Args:
        scheme: The RSA encryption scheme to test.
        hash_algorithm: (RSAES-OAEP only) The hash algorithm used.
        mgf_hash: (RSAES-OAEP only) The hash algorithm to use with MGF1.
    """
    wrapper = Path.cwd() / "rsaes_wrapper.py"
    if not wrapper.is_file():
        raise FileNotFoundError("Can't find rsaes_wrapper.py in the current directory.")

    logger.debug("Running Python RSAES wrapper")

    # Add CWD to the path, at the beginning in case this is called more than
    # once, since the previous CWD would have priority.
    sys.path.insert(0, str(Path.cwd()))

    # Before importing the wrapper we check if it's already in the loaded
    # modules, in which case we want to reload it or we would be testing the
    # wrapper loaded previously.
    imported = "rsaes_wrapper" in sys.modules.keys()

    # Import it normally.
    try:
        rsaes_wrapper = importlib.import_module("rsaes_wrapper")
    except ModuleNotFoundError as error:
        logger.debug(error)
        raise FileNotFoundError("Can't load the wrapper!") from error

    # Then reload it if necessary.
    if imported:
        logger.debug("Reloading the RSAES Python wrapper")
        rsaes_wrapper = importlib.reload(rsaes_wrapper)

    if scheme == Scheme.PKCS:
        rd = test_decrypt_pkcs(rsaes_wrapper.pkcs_decrypt)
    else:
        if hash_algorithm is None:
            raise ValueError("RSAES-OAEP requires hash_algorithm")
        rd = test_decrypt_oaep(rsaes_wrapper.oaep_decrypt, hash_algorithm, mgf_hash)

    # To de-clutter the path, remove the CWD.
    sys.path.remove(str(Path.cwd()))

    return rd


def run_rsaes_wrapper(
    language: Wrapper,
    scheme: Scheme,
    hash_algorithm: Hash | None = None,
    mgf_hash: Hash | None = None,
):
    """Runs the corresponding wrapper.

    Args:
        language: The language of the wrapper to run.
        scheme: The RSA encryption scheme to test.
        hash_algorithm: The hash algorithm used.
        mgf_hash: (RSAES-OAEP only) The hash algorithm to use with MGF1.

    Returns:
        Returns the value returned by :func:`test_decrypt_pkcs` or
        :func:`test_decrypt_oaep`.
    """
    match language:
        case Wrapper.PYTHON:
            return _run_rsaes_python_wrapper(scheme, hash_algorithm, mgf_hash)
        case _:  # pragma: no cover (mypy)
            raise ValueError("Unsupported language %s" % language)
