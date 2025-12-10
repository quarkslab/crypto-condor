"""Wrapper template for SHAKE implementations.

Usage:
    crypto-condor-cli test wrapper SHAKE shake_wrapper_example.py
"""

from Crypto.Hash import SHAKE128, SHAKE256


def CC_SHAKE_digest_shake128(data: bytes, output_length: int) -> bytes:
    """Hashes with SHAKE128."""
    return SHAKE128.new(data).read(output_length)


def CC_SHAKE_digest_shake256(data: bytes, output_length: int) -> bytes:
    """Hashes with SHAKE256."""
    return SHAKE256.new(data).read(output_length)
