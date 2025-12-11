"""Wrapper template for RSAES implementations."""


def CC_RSAES_decrypt_pkcs(secret_key: str, ciphertext: bytes) -> bytes:
    """Example function for RSAES-PKCS1-v1_5 decryption.

    Args:
        secret_key:
            The secret key to use, in PEM format.
        ciphertext:
            The ciphertext to decrypt.

    Returns:
        The plaintext. If the decryption fails, return an empty byte-array (b"").
    """
    raise NotImplementedError


def CC_RSAES_decrypt_oaep_sha256(
    secret_key: str, ciphertext: bytes, label: bytes = b""
) -> bytes:
    """Example function for RSAES-OAEP decryption with SHA-256.

    Args:
        secret_key:
            The secret key to use, in PEM format.
        ciphertext:
            The ciphertext to decrypt.
        label:
            The optional label.

    Returns:
        The plaintext. If the decryption fails, return an empty byte-array (b"").
    """


def CC_RSAES_decrypt_oaep_sha256_sha1(
    secret_key: str, ciphertext: bytes, label: bytes = b""
) -> bytes:
    """Example function for RSAES-OAEP decryption with SHA-256 and SHA-1 as MGF hash.

    Args:
        secret_key:
            The secret key to use, in PEM format.
        ciphertext:
            The ciphertext to decrypt.
        label:
            The optional label.

    Returns:
        The plaintext. If the decryption fails, return an empty byte-array (b"").
    """
    raise NotImplementedError
