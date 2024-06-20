"""SHA wrapper example 1: PyCryptodome with SHA-256."""

# We start by importing the corresponding class to hash with SHA-256.
from Crypto.Hash import SHA256


def sha(data: bytes) -> bytes:
    """Wrapper function for a SHA implementation.

    Args:
        data: The input data.

    Returns:
        The digest of the data.
    """
    # Then we can create a new instance with the message to hash, and call digest()
    # which directly returns the hash as bytes.
    return SHA256.new(data).digest()
