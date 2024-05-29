"""RSA wrapper example 1.

PyCryptodome RSASSA-PKCS1-v1.5 signatures with SHA-256.
"""

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15


def sign(secret_key: bytes, message: bytes) -> bytes:
    """Wrapper function for signature generation.

    For RSASSA-PKCS1-v1_5 and RSASSA-PSS.

    Args:
        secret_key: The key to sign with, in PEM format.
        message: The message to sign.

    Returns:
        The signature.
    """
    key = RSA.import_key(secret_key)
    h = SHA256.new(message)
    signature = pkcs1_15.new(key).sign(h)
    return signature


def pkcs_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Wrapper function for RSASSA-PKCS1-v1_5 signature verification.

    Args:
        public_key: The public key to use, in PEM format.
        message: The message that was signed.
        signature: The resulting signature.

    Returns:
        True if the signature is valid, False otherwise.
    """
    key = RSA.import_key(public_key)
    h = SHA256.new(message)
    verifier = pkcs1_15.new(key)
    try:
        verifier.verify(h, signature)
        return True
    except ValueError:
        return False


def pss_verify(
    public_key: bytes, message: bytes, signature: bytes, salt_length: int = -1
) -> bool:
    """Wrapper function for RSASSA-PSS signature verification.

    Args:
        public_key: The public key to use, in PEM format.
        message: The message that was signed.
        signature: The resulting signature.
        salt_length: The length of the salt in bytes.

    Returns:
        True if the signature is valid, False otherwise.

    Notes:
        salt_length should always be greater or equal to 0. If for some reason
        the implementation receives -1, please create an issue.
    """
    raise NotImplementedError
