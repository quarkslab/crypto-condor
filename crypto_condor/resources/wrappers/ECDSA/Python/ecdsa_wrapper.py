"""Wrapper template to test an ECDSA implementation."""


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verifies an ECDSA signature.

    Args:
        public_key:
            The public elliptic curve key. Either PEM-encoded, DER-encoded, or as
            serialized int.
        message:
            The signed message.
        signature:
            The resulting signature.

    Returns:
        True if the signature is valid, False otherwise.
    """
    ...


def sign(private_key: bytes, message: bytes) -> bytes:
    """Signs a message with ECDSA.

    Args:
        private_key:
            The private elliptic curve key. Either PEM-encoded, DER-encoded, or as
            serialized int.
        message:
            The message to sign.
    """
    ...
