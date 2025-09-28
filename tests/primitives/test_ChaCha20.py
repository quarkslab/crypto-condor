"""Module to test the ChaCha20 primitive."""

from Crypto.Cipher import ChaCha20 as pyChacha
from Crypto.Cipher import ChaCha20_Poly1305 as pyChaPoly

from crypto_condor.primitives import ChaCha20


def test_encrypt():
    """Test for :func:`crypto_condor.primitives.ChaCha20.test_encrypt`."""

    def encrypt(key: bytes, pt: bytes, nonce: bytes, init_counter: int = 0) -> bytes:
        cipher = pyChacha.new(key=key, nonce=nonce)
        if init_counter > 0:
            cipher.seek(64 * init_counter)
        return cipher.encrypt(pt)

    rd = ChaCha20.test_encrypt(encrypt, True, True)
    assert rd.check(fail_if_empty=True), str(rd)


def test_decrypt():
    """Test for :func:`crypto_condor.primitives.ChaCha20.test_decrypt`."""

    def decrypt(key: bytes, ct: bytes, nonce: bytes, init_counter: int = 0) -> bytes:
        cipher = pyChacha.new(key=key, nonce=nonce)
        if init_counter > 0:
            cipher.seek(64 * init_counter)
        return cipher.decrypt(ct)

    rd = ChaCha20.test_decrypt(decrypt, True, True)
    assert rd.check(fail_if_empty=True), str(rd)


def test_encrypt_poly():
    """Test for :func:`crypto_condor.primitives.ChaCha20.test_encrypt_poly`."""

    def encrypt_poly(
        key: bytes, pt: bytes, nonce: bytes, aad: bytes
    ) -> tuple[bytes, bytes]:
        if len(nonce) != 12:
            raise ValueError("Only RFC 7539 ChaCha20 is supported")
        cipher = pyChaPoly.new(key=key, nonce=nonce)
        if aad:
            cipher.update(aad)
        return cipher.encrypt_and_digest(pt)

    rd = ChaCha20.test_encrypt_poly(encrypt_poly, True, True)
    assert rd.check(fail_if_empty=True), str(rd)


def test_decrypt_poly():
    """Test for :func:`crypto_condor.primitives.ChaCha20.test_decrypt_poly`."""

    def decrypt_poly(
        key: bytes, ct: bytes, nonce: bytes, tag: bytes, aad: bytes
    ) -> bytes:
        if len(nonce) != 12:
            raise ValueError("Only RFC 7539 ChaCha20 is supported")
        cipher = pyChaPoly.new(key=key, nonce=nonce)
        if aad:
            cipher.update(aad)
        return cipher.decrypt_and_verify(ct, tag)

    rd = ChaCha20.test_decrypt_poly(decrypt_poly, True, True)
    assert rd.check(fail_if_empty=True), str(rd)
