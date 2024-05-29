"""Module to test RSAES."""

from typing import Any

import pytest
from Crypto.Cipher import PKCS1_OAEP, PKCS1_v1_5
from Crypto.Hash import SHA1, SHA224, SHA256, SHA384, SHA512
from Crypto.PublicKey import RSA as CryptoRSA
from Crypto.Signature import pss

from crypto_condor.primitives import RSAES
from crypto_condor.primitives.common import Console

console = Console()


def test_decrypt_pkcs115():
    """Tests :func:`crypto_condor.primitives.RSAES.test_decrypt`.

    Tests for RSAES-PKCS1-v1_5.
    """

    def _decrypt(sk: str, msg: bytes) -> bytes:
        key = CryptoRSA.import_key(sk)
        cipher = PKCS1_v1_5.new(key)
        try:
            pt = cipher.decrypt(msg, b"")
            return pt
        except ValueError:
            return b""

    results = RSAES.test_decrypt_pkcs(_decrypt)
    console.print_results(results)
    assert results.check()


PYC_HASHES: dict[str, Any] = {
    "SHA-1": SHA1,
    "SHA-224": SHA224,
    "SHA-256": SHA256,
    "SHA-384": SHA384,
    "SHA-512": SHA512,
}


@pytest.mark.parametrize(
    "sha, mgf_sha",
    [
        (RSAES.Hash.SHA_1, RSAES.Hash.SHA_1),
        (RSAES.Hash.SHA_224, RSAES.Hash.SHA_1),
        (RSAES.Hash.SHA_224, RSAES.Hash.SHA_224),
        (RSAES.Hash.SHA_256, RSAES.Hash.SHA_1),
        (RSAES.Hash.SHA_256, RSAES.Hash.SHA_256),
        (RSAES.Hash.SHA_384, RSAES.Hash.SHA_1),
        (RSAES.Hash.SHA_384, RSAES.Hash.SHA_384),
        (RSAES.Hash.SHA_512, RSAES.Hash.SHA_1),
        (RSAES.Hash.SHA_512, RSAES.Hash.SHA_512),
    ],
)
def test_decrypt_pss(sha: RSAES.Hash, mgf_sha: RSAES.Hash):
    """Tests :func:`crypto_condor.primitives.RSA.test_decrypt`.

    Tests for RSAES-OAEP.
    """

    def _decrypt(private_key: bytes, ciphertext: bytes, label: bytes) -> bytes:
        key = CryptoRSA.import_key(private_key)
        _sha = PYC_HASHES.get(sha)
        _msha = PYC_HASHES[mgf_sha]
        cipher = PKCS1_OAEP.new(
            key, _sha, mgfunc=lambda x, y: pss.MGF1(x, y, _msha), label=label
        )
        try:
            pt = cipher.decrypt(ciphertext)
            return pt
        except ValueError:
            return b""

    results = RSAES.test_decrypt_oaep(_decrypt, sha, mgf_sha)
    console.print_results(results)
    assert results.check()
