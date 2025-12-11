"""Wrapper example for RSA decryption.

Tests the implementation of RSA decryption of PyCryptodome.

There are examples of RSAES-PKCS1-v1_5, as well as RSAES-OAEP with and without MGF hash.
"""

from Crypto.Cipher import PKCS1_OAEP, PKCS1_v1_5
from Crypto.Hash import SHA1, SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pss


def CC_RSAES_decrypt_pkcs(secret_key: str, ciphertext: bytes) -> bytes:
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


def CC_RSAES_decrypt_oaep_sha256(
    secret_key: str, ciphertext: bytes, label: bytes = b""
) -> bytes:
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


def CC_RSAES_decrypt_oaep_sha256_sha1(
    secret_key: str, ciphertext: bytes, label: bytes = b""
) -> bytes:
    """Wrapper function for RSAES-OAEP decryption.

    Args:
        secret_key: The secret key to use, in PEM format.
        ciphertext: The ciphertext to decrypt.
        label: The optional label.

    Returns:
        The plaintext. If the decryption fails, return an empty byte-array (b"").
    """
    key = RSA.import_key(secret_key)
    cipher = PKCS1_OAEP.new(
        key, SHA256, mgfunc=lambda x, y: pss.MGF1(x, y, SHA1), label=label
    )
    try:
        plaintext = cipher.decrypt(ciphertext)
        return plaintext
    except ValueError:
        return b""
