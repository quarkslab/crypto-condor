"""Wrapper template for SHAKE implementations."""

from Crypto.Hash import SHAKE128


def shake(data: bytes, output_length: int) -> bytes:
    """Wrapper function for a SHAKE implementation.

    Args:
        data: The input data.
        output_length: The length of the digest in bytes.

    Return:
        The digest.
    """
    return SHAKE128.new().update(data).read(output_length)
