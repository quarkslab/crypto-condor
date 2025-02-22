#include <openssl/evp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int generic_digest(uint8_t *digest, const size_t digest_size,
                   const uint8_t *input, const size_t input_size,
                   const char *name) {
  const EVP_MD *md = EVP_get_digestbyname(name);
  if (md == NULL) {
    fprintf(stderr, "Failed to get digest %s\n", name);
    return -1;
  }

  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  if (!EVP_DigestInit_ex2(mdctx, md, NULL)) {
    fprintf(stderr, "Init failed\n");
    goto clean;
  }
  if (!EVP_DigestUpdate(mdctx, input, input_size)) {
    fprintf(stderr, "Update failed\n");
    goto clean;
  }
  if (!EVP_DigestFinalXOF(mdctx, digest, digest_size)) {
    fprintf(stderr, "Final failed\n");
    goto clean;
  }

  return 0;

clean:
  EVP_MD_CTX_free(mdctx);
  return -1;
}

int CC_SHAKE_128_digest(uint8_t *digest, const size_t digest_size,
                        const uint8_t *input, const size_t input_size) {
  return generic_digest(digest, digest_size, input, input_size, "SHAKE-128");
}

int CC_SHAKE_256_digest(uint8_t *digest, const size_t digest_size,
                        const uint8_t *input, const size_t input_size) {
  return generic_digest(digest, digest_size, input, input_size, "SHAKE-256");
}
