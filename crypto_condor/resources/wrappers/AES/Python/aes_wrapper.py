"""Wrapper template to test an AES implementation.

For detailed examples, see the documentation.

In short, you have to complete the `encrypt` and/or `decrypt` functions with the
code necessary to perform those operations. Then, when using the CLI this
wrapper will be imported and tested.

Do not change the arguments of the functions, even if you don't use all of them.
The tool expects them to be present and will likely fail if one is missing.
"""


def CC_AES_CBC_encrypt(
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


def CC_AES_CBC_decrypt(
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


def CC_AES_GCM_encrypt(
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


def CC_AES_GCM_decrypt(
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
