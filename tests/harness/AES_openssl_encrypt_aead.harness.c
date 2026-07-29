#include <openssl/evp.h>

int CC_AES_GCM_256_encrypt(uint8_t *ciphertext, size_t ciphertext_size,
                           uint8_t *mac, size_t mac_size,
                           const uint8_t *plaintext, size_t plaintext_size,
                           const uint8_t *key, size_t key_size,
                           const uint8_t *nonce, size_t nonce_size,
                           const uint8_t *aad, size_t aad_size) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  int len;

  if (!ctx)
    goto error;
  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
    goto error;
  if (1 !=
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, nonce_size, NULL)) {
    fprintf(stderr, "Failed to set IV len\n");
    goto error;
  }
  if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce))
    goto error;
  if (1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_size))
    goto error;
  if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_size))
    goto error;
  if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    goto error;
  if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, mac_size, mac))
    goto error;

  EVP_CIPHER_CTX_free(ctx);
  return 1;

error:
  EVP_CIPHER_CTX_free(ctx);
  return 0;
}

int CC_AES_CCM_256_encrypt(uint8_t *ciphertext, size_t ciphertext_size,
                           uint8_t *mac, size_t mac_size,
                           const uint8_t *plaintext, size_t plaintext_size,
                           const uint8_t *key, size_t key_size,
                           const uint8_t *nonce, size_t nonce_size,
                           const uint8_t *aad, size_t aad_size) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  int len;

  if (!ctx)
    goto error;
  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ccm(), NULL, NULL, NULL))
    goto error;
  if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, nonce_size, NULL))
    goto error;
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, mac_size, NULL);
  if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce))
    goto error;
  // Provide total plaintext length.
  if (1 != EVP_EncryptUpdate(ctx, NULL, &len, NULL, plaintext_size))
    goto error;
  // Provide any AAD data.
  if (aad_size > 0) {
    if (1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_size))
      goto error;
  }
  if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_size))
    goto error;
  if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    goto error;
  if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, mac_size, mac))
    goto error;

  EVP_CIPHER_CTX_free(ctx);
  return 1;

error:
  EVP_CIPHER_CTX_free(ctx);
  return 0;
}

int CC_AES_KW_256_encrypt(uint8_t *wrapped_key, size_t wrapped_key_size,
              const uint8_t *key_to_wrap, size_t key_size,
              const uint8_t *key, size_t key_size_wrap) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  int len = 0, final_len = 0;

  if (!ctx)
  goto error;
  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_wrap(), NULL, key, NULL))
  goto error;
  if (1 != EVP_EncryptUpdate(ctx, wrapped_key, &len, key_to_wrap, key_size))
  goto error;
  if (1 != EVP_EncryptFinal_ex(ctx, wrapped_key + len, &final_len))
  goto error;

  EVP_CIPHER_CTX_free(ctx);
  return (len + final_len > 0) ? 1 : -1;

error:
  EVP_CIPHER_CTX_free(ctx);
  return -1;
}
