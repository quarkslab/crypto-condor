"""RSA wrapper example 3.

PyCryptodome RSAES-PKCS1-v1.5 ciphertext decryption.
"""

from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA


def pkcs_decrypt(secret_key: str, ciphertext: bytes) -> bytes:
    """Wrapper function for RSAES-PKCS1-v1_5 decryption.

    Args:
        secret_key: The secret key to use, in PEM format.
        ciphertext: The ciphertext to decrypt.

    Returns:
        The plaintext. If the decryption fails, return an empty byte-array (b"").
    """
    key = RSA.import_key(secret_key)
    cipher = PKCS1_v1_5.new(key)
    try:
        plaintext = cipher.decrypt(ciphertext, b"")
        return plaintext
    except ValueError:
        return b""


def oaep_decrypt(secret_key: str, ciphertext: bytes, label: bytes = b"") -> bytes:
    """Wrapper function for RSAES-OAEP decryption.

    Args:
        secret_key: The secret key to use, in PEM format.
        ciphertext: The ciphertext to decrypt.
        label: The optional label.

    Returns:
        The plaintext. If the decryption fails, return an empty byte-array (b"").
    """
    raise NotImplementedError
