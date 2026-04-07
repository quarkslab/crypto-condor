from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def CC_AES_decrypt_CBC(key: bytes, ciphertext: bytes, iv: bytes) -> bytes:
    decryptor = Cipher(algorithms.AES(key), modes.CTR(iv)).decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext


def CC_AES_decrypt_CBC_256(key: bytes, ciphertext: bytes, iv: bytes) -> bytes:
    decryptor = Cipher(algorithms.AES(key), modes.CTR(iv)).decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext
