"""Example 1: PyCryptodome.

Using SHA-256 and any supported curve.
"""

from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS


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
    key = ECC.import_key(public_key)
    h = SHA256.new(message)
    verifier = DSS.new(key, "fips-186-3", encoding="der")
    try:
        verifier.verify(h, signature)
        return True
    except ValueError as error:
        print(error)
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
    key = ECC.import_key(private_key)
    h = SHA256.new(message)
    signer = DSS.new(key, "fips-186-3")
    signature = signer.sign(h)
    return signature
