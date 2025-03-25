"""Wrapper template for SHA implementations.

Full API documentation at:
https://quarkslab.github.io/crypto-condor/latest/wrapper-api/SHA.html

Usage:
    crypto-condor-cli test wrapper SHA sha_wrapper.py
"""


def CC_SHA_256_digest(data: bytes) -> bytes:
    """Wrapper function for a SHA-256 implementation.

    Args:
        data: The input data.

    Returns:
        The digest of the data.
    """
    raise NotImplementedError


def CC_SHA_3_384_digest(data: bytes) -> bytes:
    """Wrapper function for a SHA3-384 implementation.

    Args:
        data: The input data.

    Returns:
        The digest of the data.
    """
    raise NotImplementedError


def CC_SHA_512_224_digest(data: bytes) -> bytes:
    """Wrapper function for a SHA-512/224 implementation.

    Args:
        data: The input data.

    Returns:
        The digest of the data.
    """
    raise NotImplementedError
