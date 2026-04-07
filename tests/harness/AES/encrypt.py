from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def CC_AES_encrypt_CBC(key: bytes, plaintext: bytes, iv: bytes) -> bytes:
    encryptor = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext


def CC_AES_encrypt_CBC_256(key: bytes, plaintext: bytes, iv: bytes) -> bytes:
    encryptor = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext
