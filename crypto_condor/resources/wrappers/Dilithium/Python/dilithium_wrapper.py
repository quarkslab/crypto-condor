"""Template for te Python Dilithium wrapper.

See the documentation for a guide on how to use the template, as well as some
examples.
"""


def sign(secret_key: bytes, message: bytes) -> bytes:
    """Signs a message.

    Args:
        secret_key:
            The secret key.
        message:
            The message to sign.

    Returns:
        The computed signature.
    """
    pass


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verifies a signed message.

    Args:
        public_key:
            The public key.
        message:
            The signed message.
        signature:
            The signature to verify.

    Returns:
        True if the signature is valid, False otherwise.
    """
    pass
