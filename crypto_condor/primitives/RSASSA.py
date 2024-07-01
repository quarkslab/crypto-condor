"""Module for RSASSA."""

import importlib
import logging
import sys
from pathlib import Path
from typing import Protocol

import attrs
import strenum
from Crypto.Hash import (
    SHA1,
    SHA3_224,
    SHA3_256,
    SHA3_384,
    SHA3_512,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
)
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from rich.progress import track

from crypto_condor.primitives.common import DebugInfo, Results, ResultsDict, TestType
from crypto_condor.vectors.RSASSA import (
    Hash,
    RsaSigGenVectors,
    RsaSigVerVectors,
    Scheme,
)

# --------------------------- Module --------------------------------------------------
logger = logging.getLogger(__name__)


def __dir__():  # pragma: no cover
    return [
        # Enums
        Wrapper.__name__,
        # Protocols
        Sign.__name__,
        VerifyPkcs.__name__,
        VerifyPss.__name__,
        # Dataclasses
        # Functions
        test_sign.__name__,
        test_verify_pkcs.__name__,
        test_verify_pss.__name__,
        run_wrapper.__name__,
        # Imported
        Hash.__name__,
        Scheme.__name__,
    ]


# --------------------------- Enums ---------------------------------------------------


class Wrapper(strenum.StrEnum):
    """Available wrappers."""

    PYTHON = "Python"


# --------------------------- Protocols -----------------------------------------------


class Sign(Protocol):
    """Represents a function that signs with RSASSA-PKCS1-v1_5 or RSASSA-PSS."""

    def __call__(self, private_key: bytes, message: bytes) -> bytes:
        """Signs a message with RSA.

        Args:
            private_key: The private key in PEM format.
            message: The message to sign.

        Returns:
            The signature.
        """
        ...  # pragma: no cover (protocol)


class VerifyPkcs(Protocol):
    """Represents a function that verifies RSASSA-PKCS1-v1_5 signatures."""

    def __call__(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verifies an RSA signature.

        Args:
            public_key: The public part of the key used to sign the message in PEM
                format.
            message: The signed message.
            signature: The signature to verify.

        Returns:
            True if the signature is valid, False otherwise.
        """
        ...  # pragma: no cover (protocol)


class VerifyPss(Protocol):
    """Represents a function that verifies RSASSA-PSS signatures."""

    def __call__(
        self, public_key: bytes, message: bytes, signature: bytes, salt_length: int
    ) -> bool:
        """Verifies an RSA signature.

        Args:
            public_key: The public part of the key used to sign the message in PEM
                format.
            message: The signed message.
            signature: The signature to verify.
            salt_length: The length of the salt used in MGF1, in bytes.

        Returns:
            True if the signature is valid, False otherwise.
        """
        ...  # pragma: no cover (protocol)


# ---------------------- Dataclasses---------------------------------------------
@attrs.define
class SignData:
    """Class for storing sign debug data.

    Args:
        info: Common debug info, see :class:`crypto_condor.primitives.common.DebugInfo`.
        key: The key in PEM format.
        msg: The message to sign.
        expected_sig: The expected signature. Can be None for RSASSA-PSS as the scheme
            is probabilistic.
        sig: The resulting signature, None if the signing failed.
    """

    info: DebugInfo
    key: bytes
    msg: bytes
    expected_sig: bytes | None
    sig: bytes | None

    def __str__(self) -> str:
        """Returns a human-friendly representation."""
        s = str(self.info)
        s += f"key = {self.key.hex()}\n"
        s += f"message = {self.msg.hex()}\n"
        if self.expected_sig is not None:
            s += f"expected signature = {self.expected_sig.hex()}\n"
        if self.sig is not None:
            s += f"signature = {self.sig.hex()}\n"
        return s


@attrs.define
class VerifyData:
    """Class for storing verify debug data.

    Args:
        info: Common debug info, see :class:`crypto_condor.primitives.common.DebugInfo`.
        key: The key in PEM format.
        msg: The message that was signed.
        sig: The signature to verify.
        slen: (RSASSA-PSS only) Length of the salt in bytes.
    """

    info: DebugInfo
    key: bytes
    msg: bytes
    sig: bytes
    slen: int | None = None

    def __str__(self):
        """Returns a human-friendly representation."""
        s = f"""{str(self.info)}
key = {self.key.decode()}
message = {self.msg.hex()}
signature = {self.sig.hex()}
"""
        if self.slen is not None:
            s += f"salt length = {self.slen}\n"
        return s


# --------------------------- Internal ------------------------------------------------
def _get_hash(hash_algorithm: Hash, msg: bytes):
    """Gets a :mod:`Crypto.Hash` object.

    Args:
        hash_algorithm: The hash function to use.
        msg: The message to hash.

    Returns:
        A :mod:`Crypto.Hash` object.
    """
    match hash_algorithm:
        case "SHA-1":
            return SHA1.new(msg)
        case "SHA-224":
            return SHA224.new(msg)
        case "SHA-256":
            return SHA256.new(msg)
        case "SHA-384":
            return SHA384.new(msg)
        case "SHA-512":
            return SHA512.new(msg)
        case "SHA-512/224":
            return SHA512.new(msg, "224")
        case "SHA-512/256":
            return SHA512.new(msg, "256")
        case "SHA3-224":
            return SHA3_224.new(msg)
        case "SHA3-256":
            return SHA3_256.new(msg)
        case "SHA3-384":
            return SHA3_384.new(msg)
        case "SHA3-512":
            return SHA3_512.new(msg)


def _digest(hash_algorithm: Hash, msg: bytes) -> bytes:
    """Returns the digest of msg using the corresponding hash function."""
    h = _get_hash(hash_algorithm, msg)
    return h.digest()


# --------------------------- Test functions ------------------------------------------
def _test_sign_pss(
    sign_function: Sign,
    hash_algorithm: Hash,
    *,
    pre_hashed: bool = False,
) -> ResultsDict:
    """Tests a RSASSA-PSS signing function with NIST test vectors.

    Args:
        sign_function: The function to test, see :class:`Sign`.
        hash_algorithm: The hash algorithm to use.

    Keyword Args:
        pre_hashed: If True, the messages are hashed before passing them to
            :attr:`sign_function`.

    Returns:
        Results per file indexed by filename.
    """
    results_dict = ResultsDict()

    vectors = RsaSigGenVectors.load(Scheme.PSS, hash_algorithm)
    if vectors.nist is None:
        logger.info(
            "No test vectors available for RSASSA-PSS and %s", str(hash_algorithm)
        )
        return results_dict

    for filename, vectors_file in track(
        vectors.nist.items(), "[NIST] Signing messages"
    ):
        results = Results(
            "RSA",
            "test_sign (RSASSA-PSS)",
            "Tests a function that signs with RSASSA-PSS",
            {
                "hash_algorithm": hash_algorithm,
                "pre_hashed": pre_hashed,
                "vectors file": filename,
            },
        )
        results_dict[f"NIST/sign/{filename}"] = results
        logger.debug("Using vectors from: %s" % filename)
        n = int(vectors_file.n, 16)
        e = int(vectors_file.e, 16)
        d = int(vectors_file.d, 16)

        _key = RSA.construct((n, e, d))
        # Use a verifier instead of comparing to expected result as PSS is
        # probabilistic.
        verifier = pss.new(_key)
        key = _key.export_key()

        for tid, test in enumerate(vectors_file.tests):
            info = DebugInfo(tid, TestType.VALID, ["Compliance"])
            msg = bytes.fromhex(test.msg)
            if pre_hashed:
                msg = _digest(hash_algorithm, msg)

            try:
                sig = sign_function(key, msg)
            except Exception as error:
                info.error_msg = f"Signing error: {str(error)}"
                logger.debug("Signing error", exc_info=True)
                results.add(SignData(info, key, msg, None, None))
                continue

            try:
                verifier.verify(_get_hash(hash_algorithm, msg), sig)
                info.result = True
            except (ValueError, TypeError) as error:
                info.error_msg = str(error)
            results.add(SignData(info, key, msg, None, sig))

    return results_dict


def _test_sign_pkcs(
    sign_function: Sign,
    hash_algorithm: Hash,
    *,
    pre_hashed: bool = False,
) -> ResultsDict:
    """Tests a RSASSA-PKCS1-v1_5 signing function with NIST test vectors.

    Args:
        sign_function: The function to test, see :attr:`RsaSignFunction`.
        hash_algorithm: The hash algorithm to use.

    Keyword Args:
        pre_hashed: If True, the messages are hashed before passing them to
            :attr:`sign_function`.

    Returns:
        Results per file indexed by filename.
    """
    results_dict = ResultsDict()
    vectors = RsaSigGenVectors.load(Scheme.PKCS, hash_algorithm)
    if vectors.nist is None:
        logger.info(
            "No test vectors available for RSASSA-PKCS1-v1_5 and %s",
            str(hash_algorithm),
        )
        return results_dict

    for filename, vectors_file in track(
        vectors.nist.items(), "[NIST] Signing messages"
    ):
        results = Results(
            "RSA",
            "test_sign (RSASSA-PKCS1-v1_5)",
            "Tests a function that signs with RSASSA-PKCS1-v1_5.",
            {
                "hash_algorithm": hash_algorithm,
                "pre_hashed": pre_hashed,
                "vectors file": filename,
            },
        )
        results_dict[f"NIST/sign/{filename}"] = results
        logger.debug("Using vectors from: %s" % filename)
        n = int(vectors_file.n, 16)
        e = int(vectors_file.e, 16)
        d = int(vectors_file.d, 16)

        _key = RSA.construct((n, e, d))
        key = _key.export_key()

        for tid, test in enumerate(vectors_file.tests):
            info = DebugInfo(tid, TestType.VALID, ["Compliance"])
            msg = bytes.fromhex(test.msg)
            expected_sig = bytes.fromhex(test.sig)
            if pre_hashed:
                msg = _digest(hash_algorithm, msg)
            try:
                sig = sign_function(key, msg)
            except Exception as error:
                info.error_msg = f"Error running sign function: {str(error)}"
                logger.debug("Error running sign function", exc_info=True)
                results.add(SignData(info, key, msg, expected_sig, None))
                continue
            if sig == expected_sig:
                info.result = True
            else:
                info.error_msg = "Wrong signature"
            results.add(SignData(info, key, msg, expected_sig, sig))

    return results_dict


def test_sign(
    sign_function: Sign,
    scheme: Scheme,
    hash_algorithm: Hash,
    *,
    pre_hashed: bool = False,
) -> ResultsDict:
    """Tests a signing function with NIST test vectors.

    Args:
        sign_function: The function to test, see :attr:`Sign`.
        scheme: The signature scheme to use, e.g RSASSA-PSS.
        hash_algorithm: The hash algorithm to use.

    Keyword Args:
        pre_hashed: If True, the messages are hashed before passing them to
            :attr:`sign_function`.

    Returns:
        A dictionary containing a Results instance per vectors file, indexed by its
        filename. If there are no vectors available the dictionary is empty.
    """
    if scheme == "RSASSA-PKCS1-v1_5":
        return _test_sign_pkcs(sign_function, hash_algorithm, pre_hashed=pre_hashed)
    else:
        return _test_sign_pss(sign_function, hash_algorithm, pre_hashed=pre_hashed)


def _test_verify_pss_wycheproof(
    verify_function: VerifyPss, hash_algorithm: Hash
) -> ResultsDict:
    """Tests a RSASSA-PSS signature verification function with Wycheproof vectors.

    Args:
        verify_function: The function to test.
        hash_algorithm: The hash algorithm to use.

    Returns:
        Results per file indexed by filename.
    """
    results_dict = ResultsDict()
    vectors = RsaSigVerVectors.load(Scheme.PSS, hash_algorithm)
    if vectors.wycheproof is None:
        logger.info(
            "No Wycheproof test vectors available for RSASSA-PSS and %s",
            str(hash_algorithm),
        )
        return results_dict
    for filename, vectors_file in track(
        vectors.wycheproof.items(), "[Wycheproof] Signing messages"
    ):
        results = Results(
            "RSA",
            "test_verify (RSASSA-PSS)",
            "Tests a function that signs with RSASSA-PSS.",
            {"hash_algorithm": hash_algorithm, "vectors file": filename},
        )
        results_dict["Wycheproof/verify/{filename}"] = results
        logger.debug("Using vectors from: %s" % filename)
        # Add Wycheproof notes to results.
        results.add_notes(vectors_file.get("notes", {}))
        for group in vectors_file["testGroups"]:
            mgf_sha = Hash(group["mgfSha"])
            if mgf_sha != hash_algorithm:
                continue
            logger.debug("Using MGF1 with: %s", mgf_sha)
            pem = group["keyPem"]
            key = pem.encode()
            salt_length = int(group["sLen"])
            logger.debug(f"Salt length is: {salt_length}")
            for test in group["tests"]:
                test_type = TestType(test["result"])
                info = DebugInfo(
                    test["tcId"], test_type, test["flags"], comment=test["comment"]
                )
                msg = bytes.fromhex(test["msg"])
                sig = bytes.fromhex(test["sig"])
                try:
                    res = verify_function(key, msg, sig, salt_length)
                except Exception as error:
                    if test_type == TestType.INVALID:
                        info.result = True
                    else:
                        info.error_msg = f"Error running verify function: {str(error)}"
                        logger.debug("Error running verify function", exc_info=True)
                    results.add(VerifyData(info, key, msg, sig, salt_length))
                    continue
                match (test_type, res):
                    case (TestType.VALID, True) | (TestType.INVALID, False):
                        info.result = True
                    case TestType.VALID, False:
                        info.error_msg = "Valid signature rejected"
                    case TestType.INVALID, True:
                        info.error_msg = "Invalid signature accepted"
                    case (TestType.ACCEPTABLE, (True | False)):
                        info.result = res
                results.add(VerifyData(info, key, msg, sig, slen=salt_length))

    return results_dict


def _test_verify_pkcs_wycheproof(
    verify_function: VerifyPkcs,
    hash_algorithm: Hash,
) -> ResultsDict:
    """Tests a RSASSA-PKCS1-v1_5 signature verification function.

    Args:
        verify_function: The function to test.
        hash_algorithm: The hash function used to sign.

    Returns:
        Results per file indexed by filename.
    """
    results_dict = ResultsDict()
    vectors = RsaSigVerVectors.load(Scheme.PKCS, hash_algorithm)
    if vectors.wycheproof is None:
        logger.info(
            "No Wycheproof test vectors available for RSASSA-PKCS1-v1_5 and %s",
            str(hash_algorithm),
        )
        return results_dict
    for filename, vectors_file in vectors.wycheproof.items():
        results = Results(
            "RSA",
            "test_verify (RSASSA-PKCS1-v1_5)",
            "Tests a function that signs with RSASSA-PKCS1-v1_5.",
            {"hash_algorithm": hash_algorithm, "vectors file": filename},
        )
        results_dict[f"Wycheproof/verify/{filename}"] = results
        logger.debug("Using vectors from: %s" % filename)
        # Add Wycheproof notes to results.
        results.notes |= vectors_file.get("notes", {})
        for group in vectors_file["testGroups"]:
            pem = group["keyPem"]
            key = pem.encode()
            for test in group["tests"]:
                test_type = TestType(test["result"])
                info = DebugInfo(
                    test["tcId"], test_type, test["flags"], comment=test["comment"]
                )
                msg = bytes.fromhex(test["msg"])
                sig = bytes.fromhex(test["sig"])
                try:
                    res = verify_function(key, msg, sig)
                except Exception as error:
                    if test_type == TestType.INVALID:
                        info.result = True
                    else:
                        info.error_msg = f"Error running verify function: {str(error)}"
                        logger.debug("Error running verify function", exc_info=True)
                    results.add(VerifyData(info, key, msg, sig))
                    continue
                match (test_type, res):
                    case (TestType.VALID, True) | (TestType.INVALID, False):
                        info.result = True
                    case TestType.VALID, False:
                        info.error_msg = "Valid signature rejected"
                    case TestType.INVALID, True:
                        info.error_msg = "Invalid signature accepted"
                    case (TestType.ACCEPTABLE, (True | False)):
                        info.result = res
                results.add(VerifyData(info, key, msg, sig))

    return results_dict


def _test_verify_pkcs_nist(
    verify_function: VerifyPkcs,
    hash_algorithm: Hash,
) -> ResultsDict:
    """Tests a function that verifies RSASSA-PKCS1-v1_5 signatures.

    Args:
        verify_function: The function to test.
        hash_algorithm: The hash algorithm used to generate the signatures.

    Returns:
        Results per file indexed by filename.
    """
    results_dict = ResultsDict()
    vectors = RsaSigVerVectors.load(Scheme.PKCS, hash_algorithm)
    if vectors.nist is None:
        logger.info(
            "No NIST test vectors available for RSASSA-PKCS1-v1_5 and %s",
            str(hash_algorithm),
        )
        return results_dict
    for filename, vectors_file in track(
        vectors.nist.items(), "[NIST] Verifying RSASSA-PKCS1-v1_5 signatures."
    ):
        results = Results(
            "RSA",
            "test_verify (RSASSA-PKCS1-v1_5)",
            "Tests a function that signs with RSASSA-PKCS1-v1_5.",
            {"hash_algorithm": hash_algorithm, "vectors file": filename},
        )
        results_dict[f"NIST/verify/{filename}"] = results
        logger.debug("Using vectors from: %s" % filename)
        n = int(vectors_file.n, 16)
        for tid, test in enumerate(vectors_file.tests):
            # test.result is a bool
            test_type = TestType.VALID if test.result else TestType.INVALID
            info = DebugInfo(tid, test_type, ["Compliance"])
            e = int(test.e, 16)
            # NIST keys are given as RSA parameters. So the key has to be reconstructed
            # before passing it to the implementation.
            pk = RSA.construct((n, e))
            key = pk.export_key()
            msg = bytes.fromhex(test.msg)
            sig = bytes.fromhex(test.sig)
            try:
                res = verify_function(key, msg, sig)
            except Exception as error:
                if test_type == TestType.INVALID:
                    info.result = True
                else:
                    info.error_msg = f"Error running verify function: {str(error)}"
                    logger.debug("Error running verify function", exc_info=True)
                results.add(VerifyData(info, key, msg, sig))
                continue
            match (test_type, res):
                case (TestType.VALID, True) | (TestType.INVALID, False):
                    info.result = True
                case (TestType.VALID, False):
                    info.error_msg = "Valid signature rejected"
                case (TestType.INVALID, True):
                    info.error_msg = "Invalid signature accepted"
            results.add(VerifyData(info, key, msg, sig))

    return results_dict


def _test_verify_pss_nist(
    verify_function: VerifyPss,
    hash_algorithm: Hash,
) -> ResultsDict:
    """Tests a function that verifies RSASSA-PSS signatures.

    Args:
        verify_function: The function to test.
        hash_algorithm: The hash algorithm used to generate the signatures.

    Returns:
        Results per file indexed by filename.
    """
    results_dict = ResultsDict()
    vectors = RsaSigVerVectors.load(Scheme.PSS, hash_algorithm)
    if vectors.nist is None:
        logger.info(
            "No NIST test vectors available for RSASSA-PSS and %s",
            str(hash_algorithm),
        )
        return results_dict
    for filename, vectors_file in track(
        vectors.nist.items(), "[NIST] Verifying RSASSA-PSS signatures."
    ):
        results = Results(
            "RSA",
            "test_verify (RSASSA-PSS)",
            "Tests a function that signs with RSASSA-PSS.",
            {"hash_algorithm": hash_algorithm, "vectors file": filename},
        )
        results_dict[f"NIST/verify/{filename}"] = results
        logger.debug("Using vectors from: %s" % filename)
        n = int(vectors_file.n, 16)
        for tid, test in enumerate(vectors_file.tests):
            # test.result is a bool
            test_type = TestType.VALID if test.result else TestType.INVALID
            info = DebugInfo(tid, test_type, ["Compliance"])
            e = int(test.e, 16)
            # NIST keys are given as RSA parameters. So the key has to be reconstructed
            # before passing it to the implementation.
            pk = RSA.construct((n, e))
            key = pk.export_key()
            msg = bytes.fromhex(test.msg)
            sig = bytes.fromhex(test.sig)
            # The salt length used varies depending on hash function: for SHA-512/224
            # and SHA-512/256 the salt used has the same length as the digest (which is
            # the default value for pycryptodome).  For other tests, the salt value is
            # sometimes specified, so we calculate it's length.
            if vectors_file.sha == "sha512_224":
                slen = 224 // 8
            elif vectors_file.sha == "sha512_256":
                slen = 256 // 8
            else:
                salt = bytes.fromhex(test.salt)
                slen = len(salt)
            try:
                res = verify_function(key, msg, sig, slen)
            except Exception as error:
                if test_type == TestType.INVALID:
                    info.result = True
                else:
                    info.error_msg = f"Error running verify function: {str(error)}"
                    logger.debug("Error running verify function", exc_info=True)
                results.add(VerifyData(info, key, msg, sig, slen))
                continue
            match (test_type, res):
                case (TestType.VALID, True) | (TestType.INVALID, False):
                    info.result = True
                case (TestType.VALID, False):
                    info.error_msg = "Valid signature rejected"
                case (TestType.INVALID, True):
                    info.error_msg = "Invalid signature accepted"
            results.add(VerifyData(info, key, msg, sig, slen))

    return results_dict


def test_verify_pkcs(
    verify_function: VerifyPkcs,
    hash_algorithm: Hash,
    compliance: bool = True,
    resilience: bool = True,
) -> ResultsDict:
    """Tests a signature verification function.

    Args:
        verify_function: The function to test.
        hash_algorithm: The hash algorithm used to generate the signatures.
        compliance: Whether to use compliance test vectors.
        resilience: Whether to use resilience test vectors.

    Returns:
        A dictionary of Results, one for each vectors file, indexed by the filename. If
        there are no vectors available the dictionary is empty.
    """
    results_dict = ResultsDict()
    if compliance:
        results_dict |= _test_verify_pkcs_nist(verify_function, hash_algorithm)
    if resilience:
        results_dict |= _test_verify_pkcs_wycheproof(verify_function, hash_algorithm)
    return results_dict


def test_verify_pss(
    verify_function: VerifyPss,
    hash_algorithm: Hash,
    mgf_hash: Hash | None = None,
    compliance: bool = True,
    resilience: bool = True,
) -> ResultsDict:
    """Tests a function that verifies RSASSA-PSS signatures.

    Args:
        verify_function: The function to test.
        hash_algorithm: The hash algorithm used to generate the signatures.
        mgf_hash: The hash function to use with MGF1.
        compliance: Whether to use compliance test vectors.
        resilience: Whether to use resilience test vectors.

    Returns:
        A dictionary containing a Results instance per vectors file, indexed by its
        filename. If there are no vectors available the dictionary is empty.
    """
    results_dict = ResultsDict()
    if compliance:
        results_dict |= _test_verify_pss_nist(verify_function, hash_algorithm)
    if resilience:
        results_dict |= _test_verify_pss_wycheproof(verify_function, hash_algorithm)
    return results_dict


# --------------------------- Runners -------------------------------------------------
def _run_rsa_python_wrapper(
    scheme: Scheme,
    hash_algorithm: Hash,
    mgf_hash: Hash | None,
    run_sign: bool,
    run_verify: bool,
) -> ResultsDict:
    """Runs the Python RSA wrapper.

    Args:
        scheme: The RSA signature scheme to test.
        hash_algorithm: The hash algorithm used.
        mgf_hash: (RSASSA-PSS only) The hash algorithm to use with MGF1.
        run_sign: Whether to test signature generation.
        run_verify: Whether to test signature verification.

    Returns:
        The results of :func:`test_sign`, :func:`test_verify_pss`, or
        :func:`test_verify_pkcs` depending on the options used.
    """
    wrapper = Path.cwd() / "rsa_wrapper.py"
    if not wrapper.is_file():
        raise FileNotFoundError("Can't find rsa_wrapper.py in the current directory.")

    logger.debug("Running Python RSA wrapper")

    # Add CWD to the path, at the beginning in case this is called more than
    # once, since the previous CWD would have priority.
    sys.path.insert(0, str(Path.cwd()))

    # Before importing the wrapper we check if it's already in the loaded
    # modules, in which case we want to reload it or we would be testing the
    # wrapper loaded previously.
    imported = "rsa_wrapper" in sys.modules.keys()

    # Import it normally.
    try:
        rsa_wrapper = importlib.import_module("rsa_wrapper")
    except ModuleNotFoundError as error:
        logger.debug(error)
        raise FileNotFoundError("Can't load the wrapper!") from error

    # Then reload it if necessary.
    if imported:
        logger.debug("Reloading the RSA Python wrapper")
        rsa_wrapper = importlib.reload(rsa_wrapper)

    results_dict = ResultsDict()
    if run_sign:
        results_dict |= test_sign(rsa_wrapper.sign, scheme, hash_algorithm)
    if run_verify:
        if scheme == Scheme.PKCS:
            results_dict |= test_verify_pkcs(rsa_wrapper.pkcs_verify, hash_algorithm)
        else:
            results_dict |= test_verify_pss(
                rsa_wrapper.pss_verify, hash_algorithm, mgf_hash
            )

    # To de-clutter the path, remove the CWD.
    sys.path.remove(str(Path.cwd()))

    return results_dict


def run_wrapper(
    language: Wrapper,
    scheme: Scheme,
    hash_algorithm: Hash,
    mgf_hash: Hash | None = None,
    run_sign: bool = True,
    run_verify: bool = True,
) -> ResultsDict:
    """Runs the corresponding wrapper.

    Args:
        language: The language of the wrapper to run.
        scheme: The RSA signature scheme to test.
        hash_algorithm: The hash algorithm used.
        mgf_hash: (RSASSA-PSS only) The hash algorithm to use with MGF1.
        run_sign: Whether to test signature generation.
        run_verify: Whether to test signature verification.

    Returns:
        The results of :func:`test_sign`, :func:`test_verify_pss`, or
        :func:`test_verify_pkcs` depending on the options used.
    """
    match language:
        case Wrapper.PYTHON:
            return _run_rsa_python_wrapper(
                scheme, hash_algorithm, mgf_hash, run_sign, run_verify
            )
        case _:
            raise ValueError("Unsupported language %s" % language)
