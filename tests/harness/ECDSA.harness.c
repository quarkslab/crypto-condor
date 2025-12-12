#include <openssl/decoder.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>

const char *format = "PEM";
const char *structure = NULL;
const char *keytype = "EC";

// Define generic functions that work for both formats.
int generic_sign(const char *format, const char *digest, uint8_t *sig,
                 size_t *sig_size, const uint8_t *sk, const size_t sk_size,
                 const uint8_t *msg, const size_t msg_size);
int generic_verify(const char *format, const char *digest, const uint8_t *pk,
                   const size_t pk_size, const uint8_t *msg,
                   const size_t msg_size, const uint8_t *sig,
                   const size_t sig_size);

/* Test signing with DER keys */

int CC_ECDSA_sign_p256_sha256_DER(uint8_t *sig, size_t *sig_size,
                                  const uint8_t *sk, const size_t sk_size,
                                  const uint8_t *msg, const size_t msg_size) {
  return generic_sign("DER", "SHA-256", sig, sig_size, sk, sk_size, msg,
                      msg_size);
}

int CC_ECDSA_sign_p384_sha384_DER(uint8_t *sig, size_t *sig_size,
                                  const uint8_t *sk, const size_t sk_size,
                                  const uint8_t *msg, const size_t msg_size) {
  return generic_sign("DER", "SHA-384", sig, sig_size, sk, sk_size, msg,
                      msg_size);
}

int CC_ECDSA_sign_p521_sha512_DER(uint8_t *sig, size_t *sig_size,
                                  const uint8_t *sk, const size_t sk_size,
                                  const uint8_t *msg, const size_t msg_size) {
  return generic_sign("DER", "SHA-512", sig, sig_size, sk, sk_size, msg,
                      msg_size);
}

int CC_ECDSA_sign_p256_sha512224_DER(uint8_t *sig, size_t *sig_size,
                                     const uint8_t *sk, const size_t sk_size,
                                     const uint8_t *msg,
                                     const size_t msg_size) {
  return generic_sign("DER", "SHA-512/224", sig, sig_size, sk, sk_size, msg,
                      msg_size);
}

int CC_ECDSA_sign_p256_sha512256_DER(uint8_t *sig, size_t *sig_size,
                                     const uint8_t *sk, const size_t sk_size,
                                     const uint8_t *msg,
                                     const size_t msg_size) {
  return generic_sign("DER", "SHA-512/256", sig, sig_size, sk, sk_size, msg,
                      msg_size);
}

/* Test signing with PEM keys */

int CC_ECDSA_sign_p256_sha256_PEM(uint8_t *sig, size_t *sig_size,
                                  const uint8_t *sk, const size_t sk_size,
                                  const uint8_t *msg, const size_t msg_size) {
  return generic_sign("PEM", "SHA-256", sig, sig_size, sk, sk_size, msg,
                      msg_size);
}

int CC_ECDSA_sign_p521_sha512_PEM(uint8_t *sig, size_t *sig_size,
                                  const uint8_t *sk, const size_t sk_size,
                                  const uint8_t *msg, const size_t msg_size) {
  return generic_sign("PEM", "SHA-512", sig, sig_size, sk, sk_size, msg,
                      msg_size);
}

/* Test verifying with DER keys */

int CC_ECDSA_verify_p256_sha256_DER(const uint8_t *pk, const size_t pk_size,
                                    const uint8_t *msg, const size_t msg_size,
                                    const uint8_t *sig, const size_t sig_size) {
  return generic_verify("DER", "SHA-256", pk, pk_size, msg, msg_size, sig,
                        sig_size);
}

int CC_ECDSA_verify_p384_sha384_DER(const uint8_t *pk, const size_t pk_size,
                                    const uint8_t *msg, const size_t msg_size,
                                    const uint8_t *sig, const size_t sig_size) {
  return generic_verify("DER", "SHA-384", pk, pk_size, msg, msg_size, sig,
                        sig_size);
}

int CC_ECDSA_verify_p521_sha512_DER(const uint8_t *pk, const size_t pk_size,
                                    const uint8_t *msg, const size_t msg_size,
                                    const uint8_t *sig, const size_t sig_size) {
  return generic_verify("DER", "SHA-512", pk, pk_size, msg, msg_size, sig,
                        sig_size);
}

int CC_ECDSA_verify_p256_sha512224_DER(const uint8_t *pk, const size_t pk_size,
                                       const uint8_t *msg,
                                       const size_t msg_size,
                                       const uint8_t *sig,
                                       const size_t sig_size) {
  return generic_verify("DER", "SHA-512/224", pk, pk_size, msg, msg_size, sig,
                        sig_size);
}

int CC_ECDSA_verify_p256_sha512256_DER(const uint8_t *pk, const size_t pk_size,
                                       const uint8_t *msg,
                                       const size_t msg_size,
                                       const uint8_t *sig,
                                       const size_t sig_size) {
  return generic_verify("DER", "SHA-512/256", pk, pk_size, msg, msg_size, sig,
                        sig_size);
}

/* Test verifying with PEM keys */

int CC_ECDSA_verify_p256_sha256_PEM(const uint8_t *pk, const size_t pk_size,
                                    const uint8_t *msg, const size_t msg_size,
                                    const uint8_t *sig, const size_t sig_size) {
  return generic_verify("PEM", "SHA-256", pk, pk_size, msg, msg_size, sig,
                        sig_size);
}

int CC_ECDSA_verify_p521_sha512_PEM(const uint8_t *pk, const size_t pk_size,
                                    const uint8_t *msg, const size_t msg_size,
                                    const uint8_t *sig, const size_t sig_size) {
  return generic_verify("PEM", "SHA-512", pk, pk_size, msg, msg_size, sig,
                        sig_size);
}

/* Generic functions */

int generic_sign(const char *format, const char *digest, uint8_t *sig,
                 size_t *sig_size, const uint8_t *sk, const size_t sk_size,
                 const uint8_t *msg, const size_t msg_size) {
  EVP_PKEY *pkey = NULL;
  OSSL_DECODER_CTX *dctx =
      OSSL_DECODER_CTX_new_for_pkey(&pkey, format, NULL, "EC", 0, NULL, NULL);
  if (dctx == NULL) {
    fprintf(stderr, "Failed to create new decoder context\n");
    return 0;
  }
  size_t pdata_len = sk_size;
  if (OSSL_DECODER_from_data(dctx, &sk, &pdata_len) == 0) {
    fprintf(stderr, "Failed to read private key from data\n");
    ERR_print_errors_fp(stderr);
    return 0;
  }
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  const EVP_MD *md = EVP_get_digestbyname(digest);
  if (!EVP_DigestSignInit(mdctx, NULL, md, NULL, pkey)) {
    fprintf(stderr, "Failed to DigestSignInit\n");
    goto clean;
  }
  if (!EVP_DigestSignUpdate(mdctx, msg, msg_size)) {
    fprintf(stderr, "Failed to DigestSignUpdate\n");
    goto clean;
  }
  if (!EVP_DigestSignFinal(mdctx, sig, sig_size)) {
    fprintf(stderr, "Failed to DigestSignFinal\n");
    goto clean;
  }
  EVP_MD_CTX_free(mdctx);
  return 1;

clean:
  EVP_MD_CTX_free(mdctx);
  return 0;
}

int generic_verify(const char *format, const char *digest, const uint8_t *pk,
                   const size_t pk_size, const uint8_t *msg,
                   const size_t msg_size, const uint8_t *sig,
                   const size_t sig_size) {
  EVP_PKEY *pkey = NULL;
  OSSL_DECODER_CTX *dctx = OSSL_DECODER_CTX_new_for_pkey(
      &pkey, format, structure, keytype, 0, NULL, NULL);
  if (dctx == NULL) {
    fprintf(stderr, "Failed to create new decoder context\n");
    return -1;
  }
  size_t pdata_len = pk_size;
  if (OSSL_DECODER_from_data(dctx, &pk, &pdata_len) == 0) {
    fprintf(stderr, "Failed to read public key from data\n");
    ERR_print_errors_fp(stderr);
    return 0;
  }
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  const EVP_MD *md = EVP_get_digestbyname(digest);

  if (!EVP_DigestVerifyInit(mdctx, NULL, md, NULL, pkey)) {
    fprintf(stderr, "Failed to DigestVerifyInit\n");
    goto clean;
  }
  if (!EVP_DigestVerifyUpdate(mdctx, msg, msg_size)) {
    fprintf(stderr, "Failed to DigestVerifyUpdate\n");
    goto clean;
  }

  int retval = EVP_DigestVerifyFinal(mdctx, sig, sig_size);
  // VerifyFinal returns -1 when the signature is malformed, which is an
  // expected error for CC, so we change the return value to 0 to indicate a
  // "simple" fail.
  if (retval == -1) {
    retval = 0;
    fprintf(stderr, "Failed to DigestVerifyFinal\n");
    ERR_print_errors_fp(stderr);
  }
  EVP_MD_CTX_free(mdctx);
  return retval;

clean:
  EVP_MD_CTX_free(mdctx);
  return 0;
}
