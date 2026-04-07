from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def CC_AES_decrypt_GCM(
    key: bytes, ciphertext: bytes, nonce: bytes, aad: bytes, mac: bytes
) -> bytes:
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
    return plaintext
