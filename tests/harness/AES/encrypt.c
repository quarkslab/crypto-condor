#include <openssl/evp.h>

int CC_AES_encrypt_CBC_256(uint8_t *ciphertext, size_t ciphertext_size,
                           const uint8_t *plaintext, size_t plaintext_size,
                           const uint8_t *key, size_t key_size,
                           const uint8_t *iv, size_t iv_size) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  int len = 0;

  if (!ctx)
    goto error;
  // Disable padding, as CBC corresponds to CBC without padding.
  EVP_CIPHER_CTX_set_padding(ctx, 0);

  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    goto error;
  if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_size))
    goto error;
  if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    goto error;

  EVP_CIPHER_CTX_free(ctx);
  return 0;

error:
  EVP_CIPHER_CTX_free(ctx);
  return -1;
}
