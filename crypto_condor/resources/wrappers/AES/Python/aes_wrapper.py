"""Wrapper template to test an AES implementation.

Refer to the documentation
(https://quarkslab.github.io/crypto-condor/latest/wrapper-api/AES.html) for the full
description of the wrapper API.
"""


def CC_AES_encrypt_CBC(
    key: bytes, plaintext: bytes, *, iv: bytes | None = None
) -> bytes:
    """Encrypts with AES-CBC.

    Args:
        key: The AES key.
        plaintext: The message to encrypt.

    Keyword Args:
        iv: The IV.

    Returns:
        The plaintext.
    """
    raise NotImplementedError()


def CC_AES_decrypt_CBC(
    key: bytes, ciphertext: bytes, *, iv: bytes | None = None
) -> bytes:
    """Decrypts with AES-CBC.

    Args:
        key: The AES key.
        ciphertext: The message to decrypt.

    Keyword Args:
        iv: The IV.

    Returns:
        The plaintext.
    """
    raise NotImplementedError()


def CC_AES_encrypt_GCM(
    key: bytes,
    plaintext: bytes,
    *,
    iv: bytes | None = None,
    aad: bytes | None = None,
    mac_len: int = 0,
) -> tuple[bytes, bytes]:
    """Encrypts with AES-GCM.

    Args:
        key: The AES key.
        plaintext: The message to encrypt.

    Keyword Args:
        iv: The IV.
        aad: The associated data.
        mac_len: The length of the MAC tag.

    Returns:
        A tuple (ciphertext, tag).
    """
    raise NotImplementedError()


def CC_AES_decrypt_GCM(
    key: bytes,
    ciphertext: bytes,
    *,
    iv: bytes | None = None,
    aad: bytes | None = None,
    mac: bytes | None = None,
    mac_len: int = 0,
) -> tuple[bytes | None, bool]:
    """Decrypts with AES-GCM.

    Args:
        key: The AES key.
        ciphertext: The message to decrypt.

    Keyword Args:
        iv: The IV.
        aad: The associated data.
        mac: The MAC tag.
        mac_len: The length of the tag in bytes.

    Returns:
        The plaintext.
    """
    raise NotImplementedError()
