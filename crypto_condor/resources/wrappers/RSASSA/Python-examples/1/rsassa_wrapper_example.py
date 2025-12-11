"""RSA wrapper example 1.

PyCryptodome RSASSA-PKCS1-v1.5 signatures with SHA-256.
"""

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15, pss


def CC_RSASSA_sign_pkcs_sha256(secret_key: bytes, message: bytes) -> bytes:
    """Example function for RSA signing with PKCS padding and SHA-256.

    Args:
        secret_key:
            The key to sign with, in PEM format.
        message:
            The message to sign.

    Returns:
        The signature.
    """
    key = RSA.import_key(secret_key)
    h = SHA256.new(message)
    signature = pkcs1_15.new(key).sign(h)
    return signature


def CC_RSASSA_verify_pkcs_sha256(
    public_key: bytes, message: bytes, signature: bytes
) -> bool:
    """Example function for RSA verification with PKCS padding and SHA-256.

    Args:
        public_key:
            The public key to use, in PEM format.
        message:
            The message that was signed.
        signature:
            The resulting signature.

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


def CC_RSASSA_sign_pss_sha256(secret_key: bytes, message: bytes) -> bytes:
    """Example function for RSA signing with PSS padding and SHA-256.

    Args:
        secret_key:
            The key to sign with, in PEM format.
        message:
            The message to sign.

    Returns:
        The signature.
    """
    key = RSA.import_key(secret_key)
    h = SHA256.new(message)
    return pss.new(key).sign(h)


def CC_RSASSA_verify_pss_sha256(
    public_key: bytes, message: bytes, signature: bytes, salt_length: int = -1
) -> bool:
    """Example function for RSA verification with PSS padding and SHA-256.

    Args:
        public_key:
            The public key to use, in PEM format.
        message:
            The message that was signed.
        signature:
            The resulting signature.
        salt_length:
            The length of the salt in bytes.

    Returns:
        True if the signature is valid, False otherwise.

    Notes:
        ``salt_length`` should always be greater or equal to 0.
    """
    key = RSA.import_key(public_key)
    h = SHA256.new(message)
    verifier = pss.new(key, salt_bytes=salt_length)
    try:
        verifier.verify(h, signature)
        return True
    except ValueError:
        return False
