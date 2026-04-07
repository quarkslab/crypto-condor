#include <openssl/evp.h>
#include <stddef.h>
#include <stdint.h>

int CC_HMAC_digest_sha384(uint8_t *mac, const size_t mac_size,
                          const uint8_t *key, const size_t key_size,
                          const uint8_t *msg, const size_t msg_size) {
  EVP_MD_CTX *mdctx = NULL;
  const EVP_MD *md = NULL;
  EVP_PKEY *pkey = NULL;
  size_t req_size = 0;

  if (NULL == (mdctx = EVP_MD_CTX_new()))
    goto error_ctx_new;
  if (NULL == (md = EVP_get_digestbyname("SHA-384")))
    goto error_by_name;
  if (NULL ==
      (pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL, key, key_size)))
    goto error;
  if (1 != EVP_DigestSignInit(mdctx, NULL, md, NULL, pkey))
    goto error;
  if (1 != EVP_DigestSignUpdate(mdctx, msg, msg_size))
    goto error;
  if (1 != EVP_DigestSignFinal(mdctx, NULL, &req_size))
    goto error;
  if (req_size != mac_size)
    goto error;
  if (1 != EVP_DigestSignFinal(mdctx, mac, &req_size))
    goto error;

  EVP_MD_CTX_free(mdctx);
  EVP_PKEY_free(pkey);
  return 0;

error:
  EVP_PKEY_free(pkey);
error_by_name:
  EVP_MD_CTX_free(mdctx);
error_ctx_new:
  return -1;
}
