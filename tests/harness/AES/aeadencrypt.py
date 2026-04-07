from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def CC_AES_encrypt_GCM(
    key: bytes, plaintext: bytes, nonce: bytes, aad: bytes, mac_len: int = 0
) -> bytes:
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    return ciphertext
