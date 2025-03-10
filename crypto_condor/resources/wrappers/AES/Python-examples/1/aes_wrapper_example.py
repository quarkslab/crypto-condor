"""AES wrapper example with PyCryptodome.

Usage:
    crypto-condor-cli test wrapper AES aes_wrapper_example.py
"""

from Crypto.Cipher import AES


def CC_AES_CBC_encrypt(
    key: bytes,
    pt: bytes,
    *,
    iv: bytes | None = None,
) -> bytes:
    """Encrypts with AES-CBC."""
    return AES.new(key, AES.MODE_CBC, iv=iv).encrypt(pt)


def CC_AES_CBC_decrypt(
    key: bytes,
    ct: bytes,
    *,
    iv: bytes | None = None,
) -> bytes:
    """Decrypts with AES-CBC."""
    return AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ct)


def CC_AES_GCM_256_encrypt(
    key: bytes,
    pt: bytes,
    *,
    iv: bytes | None = None,
    aad: bytes | None = None,
    mac_len: int = 0,
) -> tuple[bytes, bytes]:
    """Encrypts with AES-256-GCM.

    Returns:
        A tuple containing the ciphertext and MAC tag.
    """
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv, mac_len=mac_len)
    if aad is not None:
        cipher.update(aad)
    return cipher.encrypt_and_digest(pt)


def CC_AES_GCM_256_decrypt(
    key: bytes,
    ct: bytes,
    *,
    iv: bytes | None = None,
    aad: bytes | None = None,
    mac: bytes | None = None,
    mac_len: int = 0,
) -> tuple[bytes | None, bool]:
    """Decrypts with AES-256-GCM.

    Returns:
        A tuple containing (bytes, True) if the tag verification succeeds, or (None,
        False) if it fails.
    """
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv, mac_len=mac_len)
    if aad is not None:
        cipher.update(aad)
    if mac is None:
        raise ValueError("GCM requires a MAC tag")
    try:
        pt = cipher.decrypt_and_verify(ct, mac)
        return pt, True
    except ValueError:
        return None, False
