#include <openssl/evp.h>

int CC_AES_GCM_256_decrypt(uint8_t *plaintext, size_t plaintext_size,
                           const uint8_t *ciphertext, size_t ciphertext_size,
                           const uint8_t *mac, size_t mac_size,
                           const uint8_t *key, size_t key_size,
                           const uint8_t *iv, size_t iv_size,
                           const uint8_t *aad, size_t aad_size) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  int len = 0;

  if (!ctx)
    goto error;
  if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
    goto error;
  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_size, NULL))
    goto error;
  if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
    goto error;
  if (aad_size > 0)
    if (!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_size))
      goto error;
  if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_size))
    goto error;
  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, mac_size, (void *)mac))
    goto error;
  if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }

  EVP_CIPHER_CTX_free(ctx);
  return 1;

error:
  EVP_CIPHER_CTX_free(ctx);
  return 0;
}

int CC_AES_CCM_256_decrypt(uint8_t *plaintext, size_t plaintext_size,
                           const uint8_t *ciphertext, size_t ciphertext_size,
                           const uint8_t *mac, size_t mac_size,
                           const uint8_t *key, size_t key_size,
                           const uint8_t *iv, size_t iv_size,
                           const uint8_t *aad, size_t aad_size) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  int len = 0;

  if (!ctx)
    goto error;
  if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_ccm(), NULL, NULL, NULL))
    goto error;
  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, iv_size, NULL))
    goto error;
  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, mac_size, (void *)mac))
    goto error;
  if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
    goto error;
  // Provide total ciphertext length.
  if (!EVP_DecryptUpdate(ctx, NULL, &len, NULL, ciphertext_size))
    goto error;
  if (aad_size > 0)
    if (!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_size))
      goto error;
  if (1 !=
      EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_size)) {
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }

  EVP_CIPHER_CTX_free(ctx);
  return 1;

error:
  EVP_CIPHER_CTX_free(ctx);
  return 0;
}
