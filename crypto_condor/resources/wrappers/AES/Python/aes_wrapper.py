"""Wrapper template to test an AES implementation.

For detailed examples, see the documentation.

In short, you have to complete the `encrypt` and/or `decrypt` functions with the
code necessary to perform those operations. Then, when using the CLI this
wrapper will be imported and tested.

Do not change the arguments of the functions, even if you don't use all of them.
The tool expects them to be present and will likely fail if one is missing.
"""


def encrypt(
    key: bytes,
    message: bytes,
    *,
    iv: bytes | None = None,
    aad: bytes | None = None,
    mac_len: int = 0,
    segment_size: int = 0,
) -> bytes | tuple[bytes, bytes]:
    """Function for encryption.

    Args:
        key:
            The cryptographic key.
        message:
            The message to encrypt.

    Keyword Args:
        iv:
            (All modes except ECB) The IV or nonce, depending on the mode of operation.
        aad:
            (AEAD modes) The associated data, it may be empty (b"").
            (Classic modes) None.
        mac_len:
            (AEAD modes) The desired length of the authentication tag in bytes.
            (Classic modes) None.
        segment_size:
            (CFB modes) The size of the segment in bits, either 8 or 128.

    Returns:
        (Classic modes) The ciphertext.
        (AEAD modes) A tuple containing the ciphertext and tag. See
        CiphertextAndTag in the documentation for the AES module.
    """
    # TO FILL
    pass


def decrypt(
    key: bytes,
    message: bytes,
    *,
    iv: bytes | None = None,
    aad: bytes | None = None,
    mac_len: int = 0,
    tag: bytes | None = None,
    segment_size: int = 0,
) -> bytes | tuple[bytes | None, bool]:
    """Function for decryption.

    Args:
        key:
            The cryptographic key.
        message:
            The message to encrypt.

    Keyword Args:
        iv:
            (All modes except ECB) The IV or nonce, depending on the mode of operation.
        aad:
            (AEAD modes) The associated data, it may be empty (b"").
            (Classic modes) None.
        mac_len:
            (AEAD modes) The expected length of the authentication tag in bytes.
            (Classic modes) None.
        tag:
            (AEAD-modes) The authentication tag.
            (Classic modes) None.
        segment_size:
            (CFB modes) The size of the segment in bits, either 8 or 128.

    Returns:
        (Classic modes) The plaintext.
        (AEAD modes) A tuple containing (plaintext, True) if the decryption was
        successful (i.e. the tag was correctly verified), (None, False)
        otherwise. See PlaintextAndBool in the documentation of the AES module.
    """
    # TO FILL
    pass
