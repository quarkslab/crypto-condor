#include <openssl/err.h>
#include <openssl/evp.h>

int CC_ChaCha20_encrypt_poly(uint8_t *ciphertext, uint8_t mac[16],
                             const uint8_t *plaintext, size_t text_size,
                             const uint8_t key[32], const uint8_t *nonce,
                             size_t nonce_size, const uint8_t *aad,
                             size_t aad_size) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  int len = 0;

  // Adhere to the RFC 7539 version with 12-byte nonces.
  if (nonce_size != 12)
    goto error;

  if (!ctx)
    goto error;

  if (1 != EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key, nonce))
    goto error;

  if (aad_size > 0) {
    if (1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_size))
      goto error;
  }

  if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, text_size))
    goto error;

  if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    goto error;

  if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, mac))
    goto error;

  EVP_CIPHER_CTX_free(ctx);
  return 1;

error:
  ERR_print_errors_fp(stderr);
  EVP_CIPHER_CTX_free(ctx);
  return 0;
}
