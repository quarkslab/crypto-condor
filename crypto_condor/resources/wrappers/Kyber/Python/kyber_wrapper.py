"""Template for the Python Kyber wrapper.

See the documentation for a guide on how to use the template, as well as some
examples.
"""


def encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
    """Generates a random secret and encapsulates it.

    Args:
        public_key:
            The public key to use for encapsulating the generated secret.

    Returns:
        A tuple (ct, ss) containing the generated secret ss and the resulting
        ciphertext ct.
    """
    pass


def decapsulate(secret_key: bytes, ciphertext: bytes) -> bytes:
    """Decapsulates a ciphertext containing a generated secret.

    Args:
        secret_key:
            The secret key to use for decapsulating the ciphertext.
        ciphertext:
            A ciphertext of the shared secret.

    Returns:
        The generated shared secret.
    """
    pass
