"""Wrapper template for RSAES implementations."""


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
    raise NotImplementedError
