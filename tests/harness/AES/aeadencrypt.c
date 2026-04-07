#include <openssl/evp.h>

int CC_AES_aeadencrypt_GCM_256(uint8_t *ciphertext, size_t ciphertext_size,
                               uint8_t *mac, size_t mac_size,
                               const uint8_t *plaintext, size_t plaintext_size,
                               const uint8_t *key, size_t key_size,
                               const uint8_t *nonce, size_t nonce_size,
                               const uint8_t *aad, size_t aad_size) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  int len = 0;

  if (!ctx)
    goto error;
  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
    goto error;
  if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, nonce_size, NULL))
    goto error;
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
  return 0;

error:
  EVP_CIPHER_CTX_free(ctx);
  return -1;
}
