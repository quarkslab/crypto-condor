#include <openssl/evp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int generic_digest(uint8_t *digest, const uint8_t *input,
                   const size_t input_size, const char *name);

int CC_SHA_256_digest(uint8_t *digest, const size_t digest_size,
                      const uint8_t *input, const size_t input_size) {
  return generic_digest(digest, input, input_size, "SHA256");
}

int CC_SHA_384_digest(uint8_t *digest, const size_t digest_size,
                      const uint8_t *input, const size_t input_size) {
  return generic_digest(digest, input, input_size, "SHA384");
}

int CC_SHA_512_digest(uint8_t *digest, const size_t digest_size,
                      const uint8_t *input, const size_t input_size) {
  return generic_digest(digest, input, input_size, "SHA512");
}

int CC_SHA_512_224_digest(uint8_t *digest, const size_t digest_size,
                      const uint8_t *input, const size_t input_size) {
  return generic_digest(digest, input, input_size, "SHA512-224");
}

int CC_SHA_3_384_digest(uint8_t *digest, const size_t digest_size,
                      const uint8_t *input, const size_t input_size) {
  return generic_digest(digest, input, input_size, "SHA3-384");
}

int generic_digest(uint8_t *digest, const uint8_t *input,
                   const size_t input_size, const char *name) {
  const EVP_MD *md = EVP_get_digestbyname(name);
  if (md == NULL) {
    fprintf(stderr, "Failed to get digest %s\n", name);
    return 0;
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
  if (!EVP_DigestFinal_ex(mdctx, digest, NULL)) {
    fprintf(stderr, "Final failed\n");
    goto clean;
  }

  EVP_MD_CTX_free(mdctx);
  return 1;

clean:
  EVP_MD_CTX_free(mdctx);
  return 0;
}
