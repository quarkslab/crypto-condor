#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <stdlib.h>

int generic_verify(const char *hash, const uint8_t *mac, const size_t mac_size,
                   const size_t md_size, const uint8_t *key,
                   const size_t key_size, const uint8_t *msg,
                   const size_t msg_size);

int CC_HMAC_verify_sha256(const uint8_t *mac, const size_t mac_size,
                          const size_t md_size, const uint8_t *key,
                          const size_t key_size, const uint8_t *msg,
                          const size_t msg_size) {
  return generic_verify("SHA-256", mac, mac_size, md_size, key, key_size, msg,
                        msg_size);
}

int CC_HMAC_verify_sha384(const uint8_t *mac, const size_t mac_size,
                          const size_t md_size, const uint8_t *key,
                          const size_t key_size, const uint8_t *msg,
                          const size_t msg_size) {
  return generic_verify("SHA-384", mac, mac_size, md_size, key, key_size, msg,
                        msg_size);
}

int CC_HMAC_verify_sha512(const uint8_t *mac, const size_t mac_size,
                          const size_t md_size, const uint8_t *key,
                          const size_t key_size, const uint8_t *msg,
                          const size_t msg_size) {
  return generic_verify("SHA-512", mac, mac_size, md_size, key, key_size, msg,
                        msg_size);
}

int CC_HMAC_verify_sha3_256(const uint8_t *mac, const size_t mac_size,
                            const size_t md_size, const uint8_t *key,
                            const size_t key_size, const uint8_t *msg,
                            const size_t msg_size) {
  return generic_verify("SHA3-256", mac, mac_size, md_size, key, key_size, msg,
                        msg_size);
}

int CC_HMAC_verify_sha3_384(const uint8_t *mac, const size_t mac_size,
                            const size_t md_size, const uint8_t *key,
                            const size_t key_size, const uint8_t *msg,
                            const size_t msg_size) {
  return generic_verify("SHA3-384", mac, mac_size, md_size, key, key_size, msg,
                        msg_size);
}
int CC_HMAC_verify_sha3_512(const uint8_t *mac, const size_t mac_size,
                            const size_t md_size, const uint8_t *key,
                            const size_t key_size, const uint8_t *msg,
                            const size_t msg_size) {
  return generic_verify("SHA3-512", mac, mac_size, md_size, key, key_size, msg,
                        msg_size);
}
int generic_verify(const char *hash, const uint8_t *mac, const size_t mac_size,
                   const size_t md_size, const uint8_t *key,
                   const size_t key_size, const uint8_t *msg,
                   const size_t msg_size) {
  EVP_MD_CTX *mdctx = NULL;
  const EVP_MD *md = NULL;
  EVP_PKEY *pkey = NULL;
  uint8_t buf[EVP_MAX_MD_SIZE];
  size_t buf_size = md_size;

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
  if (!EVP_DigestSignFinal(mdctx, buf, &buf_size)) {
    fprintf(stderr, "Failed to DigestSignFinal, error 0x%lx\n",
            ERR_get_error());
    goto error;
  }

  EVP_MD_CTX_free(mdctx);
  EVP_PKEY_free(pkey);

  return (CRYPTO_memcmp(mac, buf, mac_size) == 0);

error:
  EVP_MD_CTX_free(mdctx);
  EVP_PKEY_free(pkey);
  return -1;
}
