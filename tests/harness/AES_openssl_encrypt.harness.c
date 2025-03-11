#include <openssl/evp.h>

// Define a generic function to use for all modes.
int encrypt(const EVP_CIPHER *cipher, uint8_t *ciphertext,
            size_t ciphertext_size, const uint8_t *plaintext,
            size_t plaintext_size, const uint8_t *key, size_t key_size,
            const uint8_t *iv, size_t iv_size);

int CC_AES_ECB_256_encrypt(uint8_t *ciphertext, size_t ciphertext_size,
                           const uint8_t *plaintext, size_t plaintext_size,
                           const uint8_t *key, size_t key_size,
                           const uint8_t *iv, size_t iv_size) {
  return encrypt(EVP_aes_256_ecb(), ciphertext, ciphertext_size, plaintext,
                 plaintext_size, key, key_size, iv, iv_size);
}

int CC_AES_CBC_256_encrypt(uint8_t *ciphertext, size_t ciphertext_size,
                           const uint8_t *plaintext, size_t plaintext_size,
                           const uint8_t *key, size_t key_size,
                           const uint8_t *iv, size_t iv_size) {
  return encrypt(EVP_aes_256_cbc(), ciphertext, ciphertext_size, plaintext,
                 plaintext_size, key, key_size, iv, iv_size);
}

int CC_AES_CTR_256_encrypt(uint8_t *ciphertext, size_t ciphertext_size,
                           const uint8_t *plaintext, size_t plaintext_size,
                           const uint8_t *key, size_t key_size,
                           const uint8_t *iv, size_t iv_size) {
  return encrypt(EVP_aes_256_ctr(), ciphertext, ciphertext_size, plaintext,
                 plaintext_size, key, key_size, iv, iv_size);
}

int CC_AES_CFB8_256_encrypt(uint8_t *ciphertext, size_t ciphertext_size,
                            const uint8_t *plaintext, size_t plaintext_size,
                            const uint8_t *key, size_t key_size,
                            const uint8_t *iv, size_t iv_size) {
  return encrypt(EVP_aes_256_cfb8(), ciphertext, ciphertext_size, plaintext,
                 plaintext_size, key, key_size, iv, iv_size);
}

int CC_AES_CFB128_256_encrypt(uint8_t *ciphertext, size_t ciphertext_size,
                              const uint8_t *plaintext, size_t plaintext_size,
                              const uint8_t *key, size_t key_size,
                              const uint8_t *iv, size_t iv_size) {
  return encrypt(EVP_aes_256_cfb128(), ciphertext, ciphertext_size, plaintext,
                 plaintext_size, key, key_size, iv, iv_size);
}

// CBC-PKCS7 uses padding, unlike the other modes.
int CC_AES_CBCPKCS7_256_encrypt(uint8_t *ciphertext, size_t ciphertext_size,
                                const uint8_t *plaintext, size_t plaintext_size,
                                const uint8_t *key, size_t key_size,
                                const uint8_t *iv, size_t iv_size) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  int len = 0;
  if (!ctx)
    goto error;

  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    goto error;
  if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_size))
    goto error;
  if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    goto error;

  EVP_CIPHER_CTX_free(ctx);
  return 1;

error:
  EVP_CIPHER_CTX_free(ctx);
  return 0;
}

int encrypt(const EVP_CIPHER *cipher, uint8_t *ciphertext,
            size_t ciphertext_size, const uint8_t *plaintext,
            size_t plaintext_size, const uint8_t *key, size_t key_size,
            const uint8_t *iv, size_t iv_size) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  int len = 0;

  if (!ctx)
    goto error;
  // Disable padding, as the test vectors are without it.
  EVP_CIPHER_CTX_set_padding(ctx, 0);

  if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv))
    goto error;
  if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_size))
    goto error;
  if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    goto error;

  EVP_CIPHER_CTX_free(ctx);
  return 1;

error:
  EVP_CIPHER_CTX_free(ctx);
  return 0;
}
