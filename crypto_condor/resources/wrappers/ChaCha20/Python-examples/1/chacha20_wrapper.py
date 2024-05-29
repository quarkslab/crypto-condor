"""Example 1: PyCryptodome with ChaCha20.

An example of how to wrap an ChaCha20 implementation.

See the documentation for detailed examples.
"""

from Crypto.Cipher import ChaCha20


def encrypt(
    key: bytes,
    plaintext: bytes,
    nonce: bytes,
    *,
    init_counter: int = 0,
) -> bytes:
    """Encrypts with ChaCha20.

    Args:
        key: The symmetric key.
        plaintext: The input to encrypt.
        nonce: The nonce used for this operation.

    Keyword Args:
        init_counter: The position in the keystream to seek before the operation, in
            bytes.

    Returns:
        The resulting ciphertext.
    """
    cipher = ChaCha20.new(key=key, nonce=nonce)
    if init_counter:
        cipher.seek(64 * init_counter)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext


def decrypt(
    key: bytes,
    ciphertext: bytes,
    nonce: bytes,
    *,
    init_counter: int = 0,
) -> bytes:
    """Decrypts with ChaCha20.

    Args:
        key: The symmetric key.
        ciphertext: The cipher to decrypt.
        nonce: The nonce to use for this operation.

    Keyword Args:
        init_counter: The position in the keystream to seek before the operation, in
            bytes.

    Returns:
        The resulting ciphertext.
    """
    cipher = ChaCha20.new(key=key, nonce=nonce)
    if init_counter:
        cipher.seek(64 * init_counter)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext
