#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int generic_exchange_x509(const char *curve, uint8_t ss[512], size_t *ss_size,
                          const uint8_t *secret, const size_t secret_size,
                          const uint8_t *point, const size_t point_size);

/* Test exchange_point with P curves */
/* OpenSSL 3.0 does not support NIST B or K curves */

int CC_ECDH_exchange_x509_P256(uint8_t ss[512], size_t *ss_size,
                               const uint8_t *secret, const size_t secret_size,
                               const uint8_t *pub, const size_t pub_size) {
  return generic_exchange_x509("prime256v1", ss, ss_size, secret, secret_size,
                               pub, pub_size);
}

int CC_ECDH_exchange_x509_P384(uint8_t ss[512], size_t *ss_size,
                               const uint8_t *secret, const size_t secret_size,
                               const uint8_t *pub, const size_t pub_size) {
  return generic_exchange_x509("secp384r1", ss, ss_size, secret, secret_size,
                               pub, pub_size);
}

int CC_ECDH_exchange_x509_P521(uint8_t ss[512], size_t *ss_size,
                               const uint8_t *secret, const size_t secret_size,
                               const uint8_t *pub, const size_t pub_size) {
  return generic_exchange_x509("secp521r1", ss, ss_size, secret, secret_size,
                               pub, pub_size);
}

/**
 * Generic exchange_point function
 *
 * Uses functions deprecated in OpenSSL 3.0.
 * The fprintf statements are mostly for debugging.
 */
int generic_exchange_x509(const char *curve, uint8_t ss[512], size_t *ss_size,
                          const uint8_t *secret, const size_t secret_size,
                          const uint8_t *pub, const size_t pub_size) {

  int nid = OBJ_txt2nid(curve);
  if (nid == NID_undef) {
    fprintf(stderr, "Failed to get NID for %s\n", curve);
    return 0;
  }
  EC_KEY *ec_sk = EC_KEY_new_by_curve_name(nid);
  if (ec_sk == NULL) {
    fprintf(stderr, "Failed to create ec_sk by curve name\n");
    return 0;
  }
  BIGNUM *prv = BN_bin2bn(secret, secret_size, NULL);
  if (prv == NULL) {
    fprintf(stderr, "Failed to get BIGNUM from secret\n");
    return 0;
  }
  if (!EC_KEY_set_private_key(ec_sk, prv)) {
    fprintf(stderr, "Failed to set private key\n");
    return 0;
  }
  EVP_PKEY *sk = EVP_PKEY_new();
  if (!EVP_PKEY_set1_EC_KEY(sk, ec_sk)) {
    fprintf(stderr, "Failed to set sk\n");
    return 0;
  }

  EVP_PKEY *pk = d2i_PUBKEY(NULL, &pub, pub_size);
  if (!pk) {
    fprintf(stderr, "Failed to read pubkey from pub\n");
    return 0;
  }

  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(sk, NULL);
  if (!ctx) {
    return 0;
  }
  if (EVP_PKEY_derive_init(ctx) <= 0) {
    fprintf(stderr, "Failed to derive_init\n");
    return 0;
  }
  if (EVP_PKEY_derive_set_peer(ctx, pk) <= 0) {
    fprintf(stderr, "Failed to derive_set_peer\n");
    return 0;
  }

  if (EVP_PKEY_derive(ctx, NULL, ss_size) <= 0) {
    fprintf(stderr, "Failed to get ss_size with derive\n");
    return 0;
  }
  if (EVP_PKEY_derive(ctx, ss, ss_size) <= 0) {
    fprintf(stderr, "Failed to derive\n");
    return 0;
  }

  return 1;
}
