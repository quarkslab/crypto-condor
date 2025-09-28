"""Wrapper template to test a ChaCha20 implementation.

Refer to the documentation for a description of the arguments:
https://quarkslab.github.io/crypto-condor/latest/wrapper-api/chacha20.html

Do not change the arguments of the functions, even if you don't use all of them.
The tool expects them to be present and will likely fail if one is missing.

To test this wrapper:

    crypto-condor-cli test wrapper chacha20 chacha20_wrapper_example.py
"""


def CC_ChaCha20_encrypt(
    key: bytes, pt: bytes, nonce: bytes, init_counter: int = 0
) -> bytes:
    """Encrypts with ChaCha20."""
    raise NotImplementedError


def CC_ChaCha20_decrypt(
    key: bytes, ct: bytes, nonce: bytes, init_counter: int = 0
) -> bytes:
    """Decrypt with ChaCha20."""
    raise NotImplementedError


def CC_ChaCha20_encrypt_poly(
    key: bytes, pt: bytes, nonce: bytes, aad: bytes
) -> tuple[bytes, bytes]:
    """Encrypts with ChaCha20-Poly1305."""
    raise NotImplementedError


def CC_ChaCha20_decrypt_poly(
    key: bytes, ct: bytes, nonce: bytes, tag: bytes, aad: bytes
) -> bytes:
    """Decrypts with ChaCha20-Poly1305."""
    raise NotImplementedError
