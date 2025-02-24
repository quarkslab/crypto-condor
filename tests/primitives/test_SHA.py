"""Module to test SHA."""

import pytest
from cryptography.hazmat.primitives import hashes

from crypto_condor.primitives import SHA


@pytest.mark.parametrize("hash_algo", SHA.Algorithm)
def test_sha(hash_algo: SHA.Algorithm):
    """Tests :func:`crypto_condor.primitives.SHA.test_sha`.

    Uses :mod:`cryptography.hazmat.primitives.hashes`.
    """

    def _hash(data: bytes):
        """Directly returns the message digest."""
        match hash_algo:
            case "SHA-1":
                digest = hashes.Hash(hashes.SHA1())
            case "SHA-224":
                digest = hashes.Hash(hashes.SHA224())
            case "SHA-256":
                digest = hashes.Hash(hashes.SHA256())
            case "SHA-384":
                digest = hashes.Hash(hashes.SHA384())
            case "SHA-512":
                digest = hashes.Hash(hashes.SHA512())
            case "SHA-512/224":
                digest = hashes.Hash(hashes.SHA512_224())
            case "SHA-512/256":
                digest = hashes.Hash(hashes.SHA512_256())
            case "SHA3-224":
                digest = hashes.Hash(hashes.SHA3_224())
            case "SHA3-256":
                digest = hashes.Hash(hashes.SHA3_256())
            case "SHA3-384":
                digest = hashes.Hash(hashes.SHA3_384())
            case "SHA3-512":
                digest = hashes.Hash(hashes.SHA3_512())
            case _:
                raise ValueError("Unsupported hash %s" % hash_algo)
        digest.update(data)
        return digest.finalize()

    hash_algorithm = SHA.Algorithm(hash_algo)
    results_dict = SHA.test_digest(_hash, hash_algorithm)

    for results in results_dict.values():
        assert results.check(empty_as_fail=True)
