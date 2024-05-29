"""Example 1: PyCryptodome with GCM.

An example of how to wrap an AES implementation.

See the documentation for detailed examples.
"""

from Crypto.Cipher import AES


def encrypt(
    key: bytes,
    message: bytes,
    *,
    iv: bytes | None = None,
    aad: bytes | None = None,
    mac_len: int = 0,
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

    Returns:
        (Classic modes) The ciphertext.
        (AEAD modes) A tuple containing the ciphertext and tag. See
        CiphertextAndTag in the documentation for the AES module.
    """
    if mac_len > 0:
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv, mac_len=mac_len)
    else:
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)

    if aad is not None:
        cipher.update(aad)

    ciphertext, tag = cipher.encrypt_and_digest(message)

    return (ciphertext, tag)


def decrypt(
    key: bytes,
    message: bytes,
    *,
    iv: bytes | None = None,
    aad: bytes | None = None,
    mac: bytes | None = None,
    mac_len: int = 0,
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
        mac:
            (AEAD-modes) The authentication tag.
            (Classic modes) None.
        mac_len:
            (AEAD modes) The expected length of the authentication tag in bytes.
            (Classic modes) None.

    Returns:
        (Classic modes) The plaintext.
        (AEAD modes) A tuple containing (plaintext, True) if the decryption was
        successful (i.e. the tag was correctly verified), (None, False)
        otherwise. See PlaintextAndBool in the documentation of the AES module.
    """
    if mac is None:
        raise ValueError("A MAC is required for GCM.")

    if mac_len:
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv, mac_len=mac_len)
    else:
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)

    if aad is not None:
        cipher.update(aad)

    try:
        plaintext = cipher.decrypt_and_verify(message, mac)
        return (plaintext, True)
    except ValueError:
        return (None, False)
