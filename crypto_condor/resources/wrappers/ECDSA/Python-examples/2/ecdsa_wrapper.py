"""Example 2: cryptography.

Using SHA-256 and any supported curve.
"""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


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
    try:
        key = serialization.load_der_public_key(public_key)
    except ValueError as error:
        print(error)
        return False

    hash_algo = hashes.SHA256()

    try:
        key.verify(signature, message, ec.ECDSA(hash_algo))
        return True
    except InvalidSignature:
        return False


def sign(private_key: bytes, message: bytes) -> bytes:
    """Signs a message with ECDSA.

    Args:
        private_key:
            The private elliptic curve key. Either PEM-encoded, DER-encoded, or as
            serialized int.
        message:
            The message to sign.
    """
    key = serialization.load_der_private_key(private_key, None)
    signature = key.sign(message, ec.ECDSA(hashes.SHA256()))
    return signature
