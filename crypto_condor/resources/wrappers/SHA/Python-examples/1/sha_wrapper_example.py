"""SHA wrapper example using PyCryptodome.

Usage:
    crypto-condor-cli test wrapper SHA sha_wrapper_example.py
"""

from Crypto.Hash import SHA3_384, SHA256, SHA512


def CC_SHA_digest_sha256(data: bytes) -> bytes:
    """Test SHA-256."""
    return SHA256.new(data).digest()


def CC_SHA_digest_sha3384(data: bytes) -> bytes:
    """Test SHA3-384."""
    return SHA3_384.new(data).digest()


def CC_SHA_digest_sha512224(data: bytes) -> bytes:
    """Test SHA-512/224."""
    return SHA512.new(data, "224").digest()
