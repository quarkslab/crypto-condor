"""Wrapper template for SHAKE implementations.

Usage:
    crypto-condor-cli test wrapper SHAKE shake_wrapper_example.py
"""


def CC_SHAKE_128_digest(data: bytes, output_length: int) -> bytes:
    """Hashes with SHAKE128."""
    raise NotImplementedError()


def CC_SHAKE_256_digest(data: bytes, output_length: int) -> bytes:
    """Hashes with SHAKE256."""
    raise NotImplementedError()
