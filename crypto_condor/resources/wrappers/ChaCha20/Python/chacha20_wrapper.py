"""Wrapper template to test a ChaCha20 implementation.

For detailed examples, see the documentation.

In short, you have to complete the `encrypt` and/or `decrypt` functions with the
code necessary to perform those operations. Then, when using the CLI this
wrapper will be imported and tested.

Do not change the arguments of the functions, even if you don't use all of them.
The tool expects them to be present and will likely fail if one is missing.
"""


def encrypt(
    key: bytes,
    plaintext: bytes,
    iv: bytes,
    *,
    aad: bytes | None = None,
    init_counter: int | None = None,
) -> bytes | tuple[bytes, bytes]:
    """Encrypts with ChaCha20.

    Args:
        key:
            The symmetric key.
        plaintext:
            The input to encrypt.
        iv:
            The IV or nonce.

    Keyword Args:
        aad:
            The associated data.
        init_counter:
            The initial value of the counter (0 if None)

    Returns:
        (CHACHA20) The resulting ciphertext.
        (CHACHA20-POLY1305) A (ciphertext, tag) tuple.
    """
    # TO FILL
    pass


def decrypt(
    key: bytes,
    ciphertext: bytes,
    iv: bytes,
    *,
    tag: bytes | None = None,
    aad: bytes | None = None,
    init_counter: int | None = None,
) -> bytes | tuple[bytes | None, bool]:
    """Decrypts with ChaCha20.

    Args:
        mode:
            The mode of operation.
        key:
            The symmetric key.
        ciphertext:
            The cipher to decrypt.
        iv:
            The IV or nonce.

    Keyword Args:
        tag:
            The authentication tag.
        aad:
            The associated data.
        init_counter:
            The initial value of the counter (0 if None)

    Returns:
        (CHACHA20) The resulting ciphertext.

        (CHACHA20-POLY1305) A (ciphertext, tag) tuple.
    """
    # TO FILL
    pass
