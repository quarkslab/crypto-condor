"""Module to test RSASSA."""

import pytest
from Crypto.PublicKey import RSA as CryptoRSA
from Crypto.Signature import pkcs1_15, pss
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, utils

from crypto_condor.primitives import RSASSA
from crypto_condor.primitives.common import Console

console = Console()

HASHES = {
    "SHA-224": hashes.SHA224,
    "SHA-256": hashes.SHA256,
    "SHA-384": hashes.SHA384,
    "SHA-512": hashes.SHA512,
    "SHA-512/224": hashes.SHA512_224,
    "SHA-512/256": hashes.SHA512_256,
}


@pytest.mark.parametrize(
    "sha",
    [
        RSASSA.Hash.SHA_224,
        RSASSA.Hash.SHA_256,
        RSASSA.Hash.SHA_384,
        RSASSA.Hash.SHA_512,
        RSASSA.Hash.SHA_512_224,
        RSASSA.Hash.SHA_512_256,
    ],
)
def test_sign_pkcs1_15(sha: RSASSA.Hash):
    """Tests :func:`crypto_condor.primitives.RSA.test_sign`.

    Tests the PKCS#1 v1.5 scheme.
    """

    def _sign(private_key: bytes, message: bytes) -> bytes:
        key = CryptoRSA.import_key(private_key)
        h = RSASSA._get_hash(sha, message)
        sig = pkcs1_15.new(key).sign(h)
        return sig

    results = RSASSA.test_sign(_sign, RSASSA.Scheme.PKCS, sha)
    console.print_results(results)
    assert results.check()


@pytest.mark.parametrize(
    "sha",
    [
        RSASSA.Hash.SHA_224,
        RSASSA.Hash.SHA_256,
        RSASSA.Hash.SHA_384,
        RSASSA.Hash.SHA_512,
        RSASSA.Hash.SHA_512_224,
        RSASSA.Hash.SHA_512_256,
    ],
)
def test_sign_pss(sha: RSASSA.Hash):
    """Tests :func:`crypto_condor.primitives.RSASSA.test_sign`.

    Tests the PSS scheme.
    """

    def _sign(private_key: bytes, message: bytes) -> bytes:
        key = CryptoRSA.import_key(private_key)
        h = RSASSA._get_hash(sha, message)
        sig = pss.new(key).sign(h)
        return sig

    results = RSASSA.test_sign(_sign, RSASSA.Scheme.PSS, sha)
    console.print_results(results)
    assert results.check()


@pytest.mark.parametrize(
    "sha",
    [
        RSASSA.Hash.SHA_224,
        RSASSA.Hash.SHA_256,
        RSASSA.Hash.SHA_384,
        RSASSA.Hash.SHA_512,
        RSASSA.Hash.SHA_512_224,
        RSASSA.Hash.SHA_512_256,
    ],
)
def test_sign_pkcs1_15_pre_hashed(sha: RSASSA.Hash):
    """Tests :func:`crypto_condor.primitives.RSASSA.test_sign`.

    Tests the PKCS#1 v1.5 scheme, with pre-hashed messages.
    """

    def _sign(private_key: bytes, message: bytes) -> bytes:
        der_key = CryptoRSA.import_key(private_key)
        key = serialization.load_pem_private_key(der_key.export_key("PEM"), None)
        _hash = HASHES.get(sha)
        sig = key.sign(  # type: ignore
            message,
            padding.PKCS1v15(),  # type: ignore
            utils.Prehashed(_hash()),  # type: ignore
        )
        return sig

    results = RSASSA.test_sign(_sign, RSASSA.Scheme.PKCS, sha, pre_hashed=True)
    console.print_results(results)
    assert results.check()


@pytest.mark.xfail(reason="Verification of the produced signature fails")
@pytest.mark.parametrize(
    "sha",
    [
        RSASSA.Hash.SHA_224,
        RSASSA.Hash.SHA_256,
        RSASSA.Hash.SHA_384,
        RSASSA.Hash.SHA_512,
        RSASSA.Hash.SHA_512_224,
        RSASSA.Hash.SHA_512_256,
    ],
)
def test_sign_pss_pre_hashed(sha: RSASSA.Hash):
    """Tests :func:`crypto_condor.primitives.RSASSA.test_sign`.

    Tests the PSS scheme, with pre-hashed messages.
    """

    def _sign(private_key: bytes, message: bytes) -> bytes:
        der_key = CryptoRSA.import_key(private_key)
        key = serialization.load_pem_private_key(der_key.export_key("PEM"), None)
        _hash = HASHES[sha]
        sig = key.sign(  # type:ignore
            message,
            padding.PSS(  # type:ignore
                mgf=padding.MGF1(_hash()),  # type:ignore
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            utils.Prehashed(_hash()),  # type:ignore
        )
        return sig

    results = RSASSA.test_sign(_sign, RSASSA.Scheme.PSS, sha, pre_hashed=True)
    console.print_results(results)
    assert results.check()


@pytest.mark.parametrize("sha", RSASSA.Hash)
def test_verify_pkcs1_5(sha: RSASSA.Hash):
    """Tests :func:`crypto_condor.primitives.RSASSA.test_verify.

    Tests signature verification for RSASSA-PKCS1-v1_5.
    """

    def _verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
        key = CryptoRSA.import_key(public_key)
        h = RSASSA._get_hash(sha, message)
        verifier = pkcs1_15.new(key)
        try:
            verifier.verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False

    results_dict = RSASSA.test_verify_pkcs(_verify, sha)
    console.print_results(results_dict)
    assert results_dict.check()


@pytest.mark.parametrize(
    "sha",
    [
        RSASSA.Hash.SHA_1,
        RSASSA.Hash.SHA_224,
        RSASSA.Hash.SHA_256,
        RSASSA.Hash.SHA_384,
        RSASSA.Hash.SHA_512,
        RSASSA.Hash.SHA_512_224,
        RSASSA.Hash.SHA_512_256,
    ],
)
def test_verify_pss(sha: RSASSA.Hash):
    """Tests :func:`crypto_condor.primitives.RSASSA.test_verify`.

    Tests signature verification for RSASSA-PSS.
    """

    def _verify(
        public_key: bytes, message: bytes, signature: bytes, salt_length: int
    ) -> bool:
        key = CryptoRSA.import_key(public_key)
        h = RSASSA._get_hash(sha, message)
        verifier = pss.new(key, salt_bytes=salt_length)
        try:
            verifier.verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False

    results = RSASSA.test_verify_pss(_verify, sha)
    console.print_results(results)
    assert results.check()
