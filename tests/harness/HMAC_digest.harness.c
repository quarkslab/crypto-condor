#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <stdlib.h>

int generic_digest(const char *hash, uint8_t *mac, const size_t mac_size,
                   const uint8_t *key, const size_t key_size,
                   const uint8_t *msg, const size_t msg_size);

int CC_HMAC_digest_sha256(uint8_t *mac, const size_t mac_size,
                          const uint8_t *key, const size_t key_size,
                          const uint8_t *msg, const size_t msg_size) {
  return generic_digest("SHA-256", mac, mac_size, key, key_size, msg, msg_size);
}

int CC_HMAC_digest_sha384(uint8_t *mac, const size_t mac_size,
                          const uint8_t *key, const size_t key_size,
                          const uint8_t *msg, const size_t msg_size) {
  return generic_digest("SHA-384", mac, mac_size, key, key_size, msg, msg_size);
}

int CC_HMAC_digest_sha512(uint8_t *mac, const size_t mac_size,
                          const uint8_t *key, const size_t key_size,
                          const uint8_t *msg, const size_t msg_size) {
  return generic_digest("SHA-512", mac, mac_size, key, key_size, msg, msg_size);
}

int CC_HMAC_digest_sha3_256(uint8_t *mac, const size_t mac_size,
                          const uint8_t *key, const size_t key_size,
                          const uint8_t *msg, const size_t msg_size) {
  return generic_digest("SHA3-256", mac, mac_size, key, key_size, msg, msg_size);
}

int CC_HMAC_digest_sha3_384(uint8_t *mac, const size_t mac_size,
                          const uint8_t *key, const size_t key_size,
                          const uint8_t *msg, const size_t msg_size) {
  return generic_digest("SHA3-384", mac, mac_size, key, key_size, msg, msg_size);
}

int CC_HMAC_digest_sha3_512(uint8_t *mac, const size_t mac_size,
                          const uint8_t *key, const size_t key_size,
                          const uint8_t *msg, const size_t msg_size) {
  return generic_digest("SHA3-512", mac, mac_size, key, key_size, msg, msg_size);
}

int generic_digest(const char *hash, uint8_t *mac, const size_t mac_size,
                   const uint8_t *key, const size_t key_size,
                   const uint8_t *msg, const size_t msg_size) {
  EVP_MD_CTX *mdctx = NULL;
  const EVP_MD *md = NULL;
  EVP_PKEY *pkey = NULL;
  size_t req_size = 0;

  mdctx = EVP_MD_CTX_new();
  if (mdctx == NULL) {
    fprintf(stderr, "EVP_MD_CTX_new failed, error 0x%lx\n", ERR_get_error());
    return -1;
  }

  md = EVP_get_digestbyname(hash);
  if (md == NULL) {
    fprintf(stderr, "Failed to get digest %s by name\n", hash);
    EVP_MD_CTX_free(mdctx);
    return -1;
  }

  pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL, key, key_size);
  if (pkey == NULL) {
    fprintf(stderr, "Failed to create HMAC key\n");
    EVP_MD_CTX_free(mdctx);
    return -1;
  }

  if (!EVP_DigestSignInit(mdctx, NULL, md, NULL, pkey)) {
    fprintf(stderr, "Failed to DigestSignInit\n");
    goto error;
  }
  if (!EVP_DigestSignUpdate(mdctx, msg, msg_size)) {
    fprintf(stderr, "Failed to DigestSignUpdate\n");
    goto error;
  }
  if (!EVP_DigestSignFinal(mdctx, NULL, &req_size)) {
    fprintf(stderr, "Failed first call to DigestSignFinal\n");
    goto error;
  }
  if (req_size != mac_size) {
    fprintf(stderr, "Required size %zu does not match given size %zu\n",
            req_size, mac_size);
    goto error;
  }
  if (!EVP_DigestSignFinal(mdctx, mac, &req_size)) {
    fprintf(stderr, "Failed to DigestSignFinal\n");
    goto error;
  }

  EVP_MD_CTX_free(mdctx);
  EVP_PKEY_free(pkey);
  return 1;

error:
  EVP_MD_CTX_free(mdctx);
  EVP_PKEY_free(pkey);
  return -1;
}
