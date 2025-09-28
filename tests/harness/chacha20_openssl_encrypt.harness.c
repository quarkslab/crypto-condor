#include <openssl/err.h>
#include <openssl/evp.h>

// TODO: We use EVP_chacha20_poly1305() for both, as the test vector for
// ChaCha20 has counter=1 and it seems that there is no way to set it in EVP.
// This works with the current test vector, but will break with other values of
// counter.

int CC_ChaCha20_encrypt(uint8_t *ciphertext, const uint8_t *plaintext,
                        size_t text_size, const uint8_t key[32],
                        const uint8_t *nonce, size_t nonce_size,
                        uint32_t init_counter) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  int len = 0;

  if (!ctx)
    goto error;
  if (1 != EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key, nonce))
    goto error;
  if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, text_size))
    goto error;
  if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    goto error;

  EVP_CIPHER_CTX_free(ctx);
  return 1;

error:
  ERR_print_errors_fp(stderr);
  EVP_CIPHER_CTX_free(ctx);
  return 0;
}
