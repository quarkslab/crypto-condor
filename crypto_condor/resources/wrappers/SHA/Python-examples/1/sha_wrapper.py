"""SHA wrapper example 1: PyCryptodome with SHA-256."""

from Crypto.Hash import SHA256


def sha(data: bytes) -> bytes:
    """Wrapper function for a SHA implementation.

    Args:
        data: The input data.

    Returns:
        The digest of the data.
    """
    return SHA256.new(data).digest()
