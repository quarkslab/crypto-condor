"""Wrapper template for SHAKE implementations."""

from Crypto.Hash import SHAKE128, SHAKE256


def CC_SHAKE_128_digest(data: bytes, output_length: int) -> bytes:
    """Hashes with SHAKE128."""
    return SHAKE128.new(data).read(output_length)


def CC_SHAKE_256_digest(data: bytes, output_length: int) -> bytes:
    """Hashes with SHAKE256."""
    return SHAKE256.new(data).read(output_length)
