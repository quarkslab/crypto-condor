#include <openssl/evp.h>

int CC_AES_decrypt_CBC_256(uint8_t *plaintext, size_t plaintext_size,
                           const uint8_t *ciphertext, size_t ciphertext_size,
                           const uint8_t *key, size_t key_size,
                           const uint8_t *iv, size_t iv_size) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  int len = 0, pt_len = 0;

  if (!ctx)
    goto error;

  if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    goto error;
  // Disable padding, as CBC corresponds to CBC without padding.
  EVP_CIPHER_CTX_set_padding(ctx, 0);

  if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_size))
    goto error;
  pt_len += len;
  if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
    goto error;
  pt_len += len;

  EVP_CIPHER_CTX_free(ctx);
  return pt_len;

error:
  EVP_CIPHER_CTX_free(ctx);
  return -1;
}
