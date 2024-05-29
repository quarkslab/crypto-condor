"""RSA wrapper example 4.

PyCryptodome RSAES-OAEP ciphertext decryption with SHA-256 and MGF1 with
SHA-256.
"""

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA


def pkcs_decrypt(secret_key: str, ciphertext: bytes) -> bytes:
    """Wrapper function for RSAES-PKCS1-v1_5 decryption.

    Args:
        secret_key: The secret key to use, in PEM format.
        ciphertext: The ciphertext to decrypt.

    Returns:
        The plaintext. If the decryption fails, return an empty byte-array (b"").
    """
    raise NotImplementedError


def oaep_decrypt(secret_key: str, ciphertext: bytes, label: bytes = b"") -> bytes:
    """Wrapper function for RSAES-OAEP decryption.

    Args:
        secret_key: The secret key to use, in PEM format.
        ciphertext: The ciphertext to decrypt.
        label: The optional label.

    Returns:
        The plaintext. If the decryption fails, return an empty byte-array (b"").
    """
    key = RSA.import_key(secret_key)
    cipher = PKCS1_OAEP.new(key, SHA256, label=label)
    try:
        plaintext = cipher.decrypt(ciphertext)
        return plaintext
    except ValueError:
        return b""
