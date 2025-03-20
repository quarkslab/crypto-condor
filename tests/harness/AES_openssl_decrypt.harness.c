#include <openssl/evp.h>

int decrypt(const EVP_CIPHER *cipher, uint8_t *plaintext, size_t plaintext_size,
            const uint8_t *ciphertext, size_t ciphertext_size,
            const uint8_t *key, size_t key_size, const uint8_t *iv,
            size_t iv_size);

int CC_AES_ECB_256_decrypt(uint8_t *plaintext, size_t plaintext_size,
                           const uint8_t *ciphertext, size_t ciphertext_size,
                           const uint8_t *key, size_t key_size,
                           const uint8_t *iv, size_t iv_size) {
  return decrypt(EVP_aes_256_ecb(), plaintext, plaintext_size, ciphertext,
                 ciphertext_size, key, key_size, iv, iv_size);
}
int CC_AES_CBC_256_decrypt(uint8_t *plaintext, size_t plaintext_size,
                           const uint8_t *ciphertext, size_t ciphertext_size,
                           const uint8_t *key, size_t key_size,
                           const uint8_t *iv, size_t iv_size) {
  return decrypt(EVP_aes_256_cbc(), plaintext, plaintext_size, ciphertext,
                 ciphertext_size, key, key_size, iv, iv_size);
}
int CC_AES_CTR_256_decrypt(uint8_t *plaintext, size_t plaintext_size,
                           const uint8_t *ciphertext, size_t ciphertext_size,
                           const uint8_t *key, size_t key_size,
                           const uint8_t *iv, size_t iv_size) {
  return decrypt(EVP_aes_256_ctr(), plaintext, plaintext_size, ciphertext,
                 ciphertext_size, key, key_size, iv, iv_size);
}
int CC_AES_CFB8_256_decrypt(uint8_t *plaintext, size_t plaintext_size,
                            const uint8_t *ciphertext, size_t ciphertext_size,
                            const uint8_t *key, size_t key_size,
                            const uint8_t *iv, size_t iv_size) {
  return decrypt(EVP_aes_256_cfb8(), plaintext, plaintext_size, ciphertext,
                 ciphertext_size, key, key_size, iv, iv_size);
}
int CC_AES_CFB128_256_decrypt(uint8_t *plaintext, size_t plaintext_size,
                              const uint8_t *ciphertext, size_t ciphertext_size,
                              const uint8_t *key, size_t key_size,
                              const uint8_t *iv, size_t iv_size) {
  return decrypt(EVP_aes_256_cfb128(), plaintext, plaintext_size, ciphertext,
                 ciphertext_size, key, key_size, iv, iv_size);
}

int CC_AES_CBCPKCS7_256_decrypt(uint8_t *plaintext, size_t plaintext_size,
                              const uint8_t *ciphertext, size_t ciphertext_size,
                              const uint8_t *key, size_t key_size,
                              const uint8_t *iv, size_t iv_size) {
  int pt_len = 0, len = 0;
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
    goto error;

  if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    goto error;
  if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_size))
    goto error;
  pt_len += len;
  if (!EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
    goto error;
  pt_len += len;

  EVP_CIPHER_CTX_free(ctx);
  return pt_len;

error:
  EVP_CIPHER_CTX_free(ctx);
  return -1;
}

int decrypt(const EVP_CIPHER *cipher, uint8_t *plaintext, size_t plaintext_size,
            const uint8_t *ciphertext, size_t ciphertext_size,
            const uint8_t *key, size_t key_size, const uint8_t *iv,
            size_t iv_size) {
  int len = 0, pt_len = 0;
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

  if (!ctx)
    goto error;

  if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv))
    goto error;
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
