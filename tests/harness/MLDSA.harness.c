#include <dlfcn.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "openssl/evp.h"
#include "openssl/err.h"
#include "openssl/core_names.h"

static const uint8_t OID_SHA2_224[] = {0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x04};
static const uint8_t OID_SHA2_256[] = {0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01};
static const uint8_t OID_SHA2_384[] = {0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x02};
static const uint8_t OID_SHA2_512[] = {0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x03};
static const uint8_t OID_SHA2_512_224[] = {0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x05};
static const uint8_t OID_SHA2_512_256[] = {0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x06};
static const uint8_t OID_SHA3_224[] = {0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x07};
static const uint8_t OID_SHA3_256[] = {0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x08};
static const uint8_t OID_SHA3_384[] = {0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x09};
static const uint8_t OID_SHA3_512[] = {0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x0A};
static const uint8_t OID_SHAKE_128[] = {0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x0B};
static const uint8_t OID_SHAKE_256[] = {0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x0C};

static const uint8_t *get_oid(const char *ph, size_t *oid_len) {
  *oid_len = 11;
  if (strncmp(ph, "SHA2-224", 8) == 0) return OID_SHA2_224;
  if (strncmp(ph, "SHA2-256", 8) == 0) return OID_SHA2_256;
  if (strncmp(ph, "SHA2-384", 8) == 0) return OID_SHA2_384;
  if (strncmp(ph, "SHA2-512/224", 12) == 0) return OID_SHA2_512_224;
  if (strncmp(ph, "SHA2-512/256", 12) == 0) return OID_SHA2_512_256;
  if (strncmp(ph, "SHA2-512", 8) == 0) return OID_SHA2_512;
  if (strncmp(ph, "SHA3-224", 8) == 0) return OID_SHA3_224;
  if (strncmp(ph, "SHA3-256", 8) == 0) return OID_SHA3_256;
  if (strncmp(ph, "SHA3-384", 8) == 0) return OID_SHA3_384;
  if (strncmp(ph, "SHA3-512", 8) == 0) return OID_SHA3_512;
  if (strncmp(ph, "SHAKE-128", 9) == 0) return OID_SHAKE_128;
  if (strncmp(ph, "SHAKE-256", 9) == 0) return OID_SHAKE_256;
  fprintf(stderr, "Unknown hash algorithm: %s\n", ph);
  return NULL;
}

void *get_lib_handle(const char lib_name[]) {
  void *handle;
  char libdir[PATH_MAX];

  snprintf(libdir, PATH_MAX, "%s/%s/%s", getenv("HOME"),
           ".local/share/crypto-condor/MLDSA", lib_name);
  handle = dlopen(libdir, RTLD_LAZY);
  if (!handle) {
    fprintf(stderr, "dlopen error: %s\n", dlerror());
    exit(EXIT_FAILURE);
  }
  return handle;
}

void *get_func(void *handle, const char func_name[]) {
  void *func;
  func = dlsym(handle, func_name);
  if (!func) {
    fprintf(stderr, "dlsym error: %s\n", dlerror());
    dlclose(handle);
    exit(EXIT_FAILURE);
  }
  return func;
}

static int hash_message(const char *ph, const uint8_t *msg, size_t msg_size,
                        uint8_t **dgst, size_t *dgst_len) {
  EVP_MD *md = NULL;
  EVP_MD_CTX *ctx = NULL;
  unsigned int ulen = 0;
  int ret = 0;

  md = EVP_MD_fetch(NULL, ph, NULL);
  if (md == NULL) {
    fprintf(stderr, "EVP_MD_fetch failed for %s\n", ph);
    goto end;
  }
  ctx = EVP_MD_CTX_new();
  if (ctx == NULL) goto end;

  if (strncmp(ph, "SHAKE-128", 9) == 0) {
    *dgst_len = 32;
    if (1 != EVP_DigestInit_ex(ctx, md, NULL)) goto end;
    if (1 != EVP_DigestUpdate(ctx, msg, msg_size)) goto end;
    *dgst = (uint8_t *)OPENSSL_malloc(*dgst_len);
    if (*dgst == NULL) goto end;
    if (1 != EVP_DigestFinalXOF(ctx, *dgst, *dgst_len)) goto end;
  } else if (strncmp(ph, "SHAKE-256", 9) == 0) {
    *dgst_len = 64;
    if (1 != EVP_DigestInit_ex(ctx, md, NULL)) goto end;
    if (1 != EVP_DigestUpdate(ctx, msg, msg_size)) goto end;
    *dgst = (uint8_t *)OPENSSL_malloc(*dgst_len);
    if (*dgst == NULL) goto end;
    if (1 != EVP_DigestFinalXOF(ctx, *dgst, *dgst_len)) goto end;
  } else {
    if (1 != EVP_DigestInit_ex(ctx, md, NULL)) goto end;
    if (1 != EVP_DigestUpdate(ctx, msg, msg_size)) goto end;
    *dgst = (uint8_t *)OPENSSL_malloc(EVP_MD_get_size(md));
    if (*dgst == NULL) goto end;
    if (1 != EVP_DigestFinal_ex(ctx, *dgst, &ulen)) goto end;
    *dgst_len = ulen;
  }
  ret = 1;

end:
  EVP_MD_free(md);
  EVP_MD_CTX_free(ctx);
  return ret;
}

/* ---- Build prehash prefix ---- */

/*
 * Prehash prefix: 0x01 || ctxlen || ctx || OID(hash)
 * Max size: 1 + 1 + 255 + 11 = 268 bytes.
 */
static int build_prehash_prefix(const uint8_t *ctx, size_t ctx_size,
                                const char *ph,
                                uint8_t *pre, size_t *pre_len) {
  size_t oid_len = 0;
  const uint8_t *oid = get_oid(ph, &oid_len);
  if (oid == NULL) return 0;

  size_t off = 0;
  pre[off++] = 0x01;  /* prehash mode byte */
  pre[off++] = (uint8_t)ctx_size;
  if (ctx_size > 0) {
    memcpy(pre + off, ctx, ctx_size);
    off += ctx_size;
  }
  memcpy(pre + off, oid, oid_len);
  off += oid_len;

  *pre_len = off;
  return 1;
}

// Because of ref API, sign_internal is necessary for prehash.
// We also set rnd = 00*32 since deterministic and hedged path are the same in this case.
static int generic_sign_internal(const char *lib_name, const char *func_name,
                                uint8_t *sig, size_t sig_size,
                                const uint8_t *msg, size_t msg_size,
                                const uint8_t *ctx, size_t ctx_size,
                                const uint8_t *sk, size_t sk_size,
                                const char *ph, size_t ph_size) {
  void *handle = NULL;
  int (*sign_internal)(uint8_t *, size_t *, const uint8_t *, size_t,
                    const uint8_t *, size_t, const uint8_t[32],
                    const uint8_t *) = NULL;
  uint8_t *dgst = NULL;
  size_t dgst_len = 0;
  uint8_t pre[268];
  size_t pre_len = 0;
  uint8_t rnd[32] = {0};
  size_t r_siglen = 0;

  int ret = -1;

  handle = get_lib_handle(lib_name);
  sign_internal = get_func(handle, func_name);

  if (ph_size > 0) {
    // prehash

    if (1 != hash_message(ph, msg, msg_size, &dgst, &dgst_len)) {
      fprintf(stderr, "Failed to hash message\n");
      goto end;
    }
    if (1 != build_prehash_prefix(ctx, ctx_size, ph, pre, &pre_len)) {
      fprintf(stderr, "Failed to build prehash prefix\n");
      goto end;
    }

    sign_internal(sig, &r_siglen, dgst, dgst_len, pre, pre_len, rnd, sk);

    if (r_siglen != 0)
      ret = 0;
  } else {
    // pure
    pre[0] = 0;
    pre[1] = (uint8_t)ctx_size;
    if (ctx_size > 0)
      memcpy(pre + 2, ctx, ctx_size);

    pre_len = 2 + ctx_size;

    sign_internal(sig, &r_siglen, msg, msg_size, pre, pre_len, rnd, sk);

    if (r_siglen != 0)
      ret = 0;
  }

end:
  if (dgst) OPENSSL_free(dgst);
  if (handle) dlclose(handle);
  return ret;
}

// Because of ref API, verify_internal is necessary for prehash.
static int generic_verify_internal(const char *lib_name, const char *func_name,
                                  const uint8_t *sig, size_t sig_size,
                                  const uint8_t *msg, size_t msg_size,
                                  const uint8_t *ctx, size_t ctx_size,
                                  const uint8_t *pk, size_t pk_size,
                                  const char *ph, size_t ph_size) {
  void *handle = NULL;
  int (*verify_internal)(const uint8_t *, size_t, const uint8_t *, size_t,
                         const uint8_t *, size_t, const uint8_t *) = NULL;
  uint8_t *dgst = NULL;
  size_t dgst_len = 0;
  uint8_t pre[268];
  size_t pre_len = 0;

  int ret = -1;

  handle = get_lib_handle(lib_name);
  verify_internal = get_func(handle, func_name);

  if (ph_size > 0) {
    // prehash
    if (1 != hash_message(ph, msg, msg_size, &dgst, &dgst_len)) {
      fprintf(stderr, "Failed to hash message\n");
      goto end;
    }
    if (1 != build_prehash_prefix(ctx, ctx_size, ph, pre, &pre_len)) {
      fprintf(stderr, "Failed to build prehash prefix\n");
      goto end;
    }

    ret = verify_internal(sig, sig_size, dgst, dgst_len, pre, pre_len, pk);
  } else {
    // pure

    pre[0] = 0;
    pre[1] = (uint8_t)ctx_size;
    if (ctx_size > 0)
      memcpy(pre + 2, ctx, ctx_size);

    pre_len = 2 + ctx_size;

    ret = verify_internal(sig, sig_size, msg, msg_size, pre, pre_len, pk);
  }

end:
  if (dgst) OPENSSL_free(dgst);
  if (handle) dlclose(handle);
  return ret;
}

/* KEYGEN */

void CC_MLDSA_44_keygen(uint8_t *pk, size_t pklen, uint8_t *sk, size_t sklen,
                        const uint8_t *seed, size_t seedlen) {
  void *handle = get_lib_handle("MLDSA-keygen-44.so");
  void (*kg)(uint8_t *, size_t, uint8_t *, size_t, const uint8_t *, size_t);
  kg = get_func(handle, "CC_MLDSA_44_keygen_impl");
  kg(pk, pklen, sk, sklen, seed, seedlen);
  dlclose(handle);
}

void CC_MLDSA_65_keygen(uint8_t *pk, size_t pklen, uint8_t *sk, size_t sklen,
                        const uint8_t *seed, size_t seedlen) {
  void *handle = get_lib_handle("MLDSA-keygen-65.so");
  void (*kg)(uint8_t *, size_t, uint8_t *, size_t, const uint8_t *, size_t);
  kg = get_func(handle, "CC_MLDSA_65_keygen_impl");
  kg(pk, pklen, sk, sklen, seed, seedlen);
  dlclose(handle);
}

void CC_MLDSA_87_keygen(uint8_t *pk, size_t pklen, uint8_t *sk, size_t sklen,
                        const uint8_t *seed, size_t seedlen) {
  void *handle = get_lib_handle("MLDSA-keygen-87.so");
  void (*kg)(uint8_t *, size_t, uint8_t *, size_t, const uint8_t *, size_t);
  kg = get_func(handle, "CC_MLDSA_87_keygen_impl");
  kg(pk, pklen, sk, sklen, seed, seedlen);
  dlclose(handle);
}

/* SIGN prehash */

void CC_MLDSA_44_sign_prehash(uint8_t *sig, size_t siglen,
                               const uint8_t *msg, size_t msglen,
                               const uint8_t *ctx, size_t ctxlen,
                               const uint8_t *sk, size_t sklen,
                               const char *ph, size_t phlen) {
  generic_sign_internal("ML-DSA-44-ref.so",
                       "pqcrystals_dilithium2_ref_signature_internal",
                       sig, siglen, msg, msglen, ctx, ctxlen, sk, sklen, ph, phlen);
}

void CC_MLDSA_65_sign_prehash(uint8_t *sig, size_t siglen,
                               const uint8_t *msg, size_t msglen,
                               const uint8_t *ctx, size_t ctxlen,
                               const uint8_t *sk, size_t sklen,
                               const char *ph, size_t phlen) {
  generic_sign_internal("ML-DSA-65-ref.so",
                       "pqcrystals_dilithium3_ref_signature_internal",
                       sig, siglen, msg, msglen, ctx, ctxlen, sk, sklen, ph, phlen);
}

void CC_MLDSA_87_sign_prehash(uint8_t *sig, size_t siglen,
                               const uint8_t *msg, size_t msglen,
                               const uint8_t *ctx, size_t ctxlen,
                               const uint8_t *sk, size_t sklen,
                               const char *ph, size_t phlen) {
  generic_sign_internal("ML-DSA-87-ref.so",
                       "pqcrystals_dilithium5_ref_signature_internal",
                       sig, siglen, msg, msglen, ctx, ctxlen, sk, sklen, ph, phlen);
}

/* sign_deterministic */

void CC_MLDSA_44_sign_deterministic_prehash(uint8_t *sig, size_t siglen,
                               const uint8_t *msg, size_t msglen,
                               const uint8_t *ctx, size_t ctxlen,
                               const uint8_t *sk, size_t sklen,
                               const char *ph, size_t phlen) {
  generic_sign_internal("ML-DSA-44-ref.so",
                       "pqcrystals_dilithium2_ref_signature_internal",
                       sig, siglen, msg, msglen, ctx, ctxlen, sk, sklen, ph, phlen);
}

void CC_MLDSA_44_sign_deterministic_pure(uint8_t *sig, size_t siglen,
                               const uint8_t *msg, size_t msglen,
                               const uint8_t *ctx, size_t ctxlen,
                               const uint8_t *sk, size_t sklen) {
  generic_sign_internal("ML-DSA-44-ref.so",
                       "pqcrystals_dilithium2_ref_signature_internal",
                       sig, siglen, msg, msglen, ctx, ctxlen, sk, sklen, NULL, 0);
}

void CC_MLDSA_65_sign_deterministic_prehash(uint8_t *sig, size_t siglen,
                               const uint8_t *msg, size_t msglen,
                               const uint8_t *ctx, size_t ctxlen,
                               const uint8_t *sk, size_t sklen,
                               const char *ph, size_t phlen) {
  generic_sign_internal("ML-DSA-65-ref.so",
                       "pqcrystals_dilithium3_ref_signature_internal",
                       sig, siglen, msg, msglen, ctx, ctxlen, sk, sklen, ph, phlen);
}

void CC_MLDSA_65_sign_deterministic_pure(uint8_t *sig, size_t siglen,
                               const uint8_t *msg, size_t msglen,
                               const uint8_t *ctx, size_t ctxlen,
                               const uint8_t *sk, size_t sklen,
                               const char *ph, size_t phlen) {
  generic_sign_internal("ML-DSA-65-ref.so",
                       "pqcrystals_dilithium3_ref_signature_internal",
                       sig, siglen, msg, msglen, ctx, ctxlen, sk, sklen, NULL, 0);
}

void CC_MLDSA_87_sign_deterministic_prehash(uint8_t *sig, size_t siglen,
                               const uint8_t *msg, size_t msglen,
                               const uint8_t *ctx, size_t ctxlen,
                               const uint8_t *sk, size_t sklen,
                               const char *ph, size_t phlen) {
  generic_sign_internal("ML-DSA-87-ref.so",
                       "pqcrystals_dilithium5_ref_signature_internal",
                       sig, siglen, msg, msglen, ctx, ctxlen, sk, sklen, ph, phlen);
}

void CC_MLDSA_87_sign_deterministic_pure(uint8_t *sig, size_t siglen,
                               const uint8_t *msg, size_t msglen,
                               const uint8_t *ctx, size_t ctxlen,
                               const uint8_t *sk, size_t sklen,
                               const char *ph, size_t phlen) {
  generic_sign_internal("ML-DSA-87-ref.so",
                       "pqcrystals_dilithium5_ref_signature_internal",
                       sig, siglen, msg, msglen, ctx, ctxlen, sk, sklen, NULL, 0);
}

/* VERIFY prehash */

int CC_MLDSA_44_verify_prehash(const uint8_t *sig, size_t siglen,
                                const uint8_t *msg, size_t msglen,
                                const uint8_t *ctx, size_t ctxlen,
                                const uint8_t *pk, size_t pklen,
                                const char *ph, size_t phlen) {
  return generic_verify_internal("ML-DSA-44-ref.so",
                                "pqcrystals_dilithium2_ref_verify_internal",
                                sig, siglen, msg, msglen, ctx, ctxlen, pk, pklen, ph, phlen);
}

int CC_MLDSA_65_verify_prehash(const uint8_t *sig, size_t siglen,
                                const uint8_t *msg, size_t msglen,
                                const uint8_t *ctx, size_t ctxlen,
                                const uint8_t *pk, size_t pklen,
                                const char *ph, size_t phlen) {
  return generic_verify_internal("ML-DSA-65-ref.so",
                                "pqcrystals_dilithium3_ref_verify_internal",
                                sig, siglen, msg, msglen, ctx, ctxlen, pk, pklen, ph, phlen);
}

int CC_MLDSA_87_verify_prehash(const uint8_t *sig, size_t siglen,
                                const uint8_t *msg, size_t msglen,
                                const uint8_t *ctx, size_t ctxlen,
                                const uint8_t *pk, size_t pklen,
                                const char *ph, size_t phlen) {
  return generic_verify_internal("ML-DSA-87-ref.so",
                                "pqcrystals_dilithium5_ref_verify_internal",
                                sig, siglen, msg, msglen, ctx, ctxlen, pk, pklen, ph, phlen);
}

/* SIGN pure */

void CC_MLDSA_44_sign_pure(uint8_t *sig, size_t siglen, const uint8_t *msg, size_t msglen, const uint8_t *ctx, size_t ctxlen, const uint8_t *sk, size_t sklen) {
  void *handle = get_lib_handle("ML-DSA-44-ref.so");
  void (*sign)(uint8_t *, size_t *, const uint8_t *, const size_t, const uint8_t *, const size_t, const uint8_t *);
  sign = get_func(handle, "pqcrystals_dilithium2_ref_signature");
  size_t r_siglen;
  sign(sig, &r_siglen, msg, msglen, ctx, ctxlen, sk);
  dlclose(handle);
}

void CC_MLDSA_65_sign_pure(uint8_t *sig, size_t siglen, const uint8_t *msg, size_t msglen, const uint8_t *ctx, size_t ctxlen, const uint8_t *sk, size_t sklen) {
  void *handle = get_lib_handle("ML-DSA-65-ref.so");
  void (*sign)(uint8_t *, size_t *, const uint8_t *, const size_t, const uint8_t *, const size_t, const uint8_t *);
  sign = get_func(handle, "pqcrystals_dilithium3_ref_signature");
  size_t r_siglen;
  sign(sig, &r_siglen, msg, msglen, ctx, ctxlen, sk);
  dlclose(handle);
}

void CC_MLDSA_87_sign_pure(uint8_t *sig, size_t siglen, const uint8_t *msg, size_t msglen, const uint8_t *ctx, size_t ctxlen, const uint8_t *sk, size_t sklen) {
  void *handle = get_lib_handle("ML-DSA-87-ref.so");
  void (*sign)(uint8_t *, size_t *, const uint8_t *, const size_t, const uint8_t *, const size_t, const uint8_t *);
  sign = get_func(handle, "pqcrystals_dilithium5_ref_signature");
  size_t r_siglen;
  sign(sig, &r_siglen, msg, msglen, ctx, ctxlen, sk);
  dlclose(handle);
}

/* VERIFY pure */

int CC_MLDSA_44_verify_pure(const uint8_t *sig, size_t siglen, const uint8_t *msg, size_t msglen, const uint8_t *ctx, size_t ctxlen, const uint8_t *pk, size_t pklen) {
  void *handle = get_lib_handle("ML-DSA-44-ref.so");
  int (*verify)(const uint8_t *, size_t, const uint8_t *, const size_t, const uint8_t *, const size_t, const uint8_t *);
  verify = get_func(handle, "pqcrystals_dilithium2_ref_verify");
  int res = verify(sig, siglen, msg, msglen, ctx, ctxlen, pk);
  dlclose(handle);
  return res;
}

int CC_MLDSA_65_verify_pure(const uint8_t *sig, size_t siglen, const uint8_t *msg, size_t msglen, const uint8_t *ctx, size_t ctxlen, const uint8_t *pk, size_t pklen) {
  void *handle = get_lib_handle("ML-DSA-65-ref.so");
  int (*verify)(const uint8_t *, size_t, const uint8_t *, const size_t, const uint8_t *, const size_t, const uint8_t *);
  verify = get_func(handle, "pqcrystals_dilithium3_ref_verify");
  int res = verify(sig, siglen, msg, msglen, ctx, ctxlen, pk);
  dlclose(handle);
  return res;
}

int CC_MLDSA_87_verify_pure(const uint8_t *sig, size_t siglen, const uint8_t *msg, size_t msglen, const uint8_t *ctx, size_t ctxlen, const uint8_t *pk, size_t pklen) {
  void *handle = get_lib_handle("ML-DSA-87-ref.so");
  int (*verify)(const uint8_t *, size_t, const uint8_t *, const size_t, const uint8_t *, const size_t, const uint8_t *);
  verify = get_func(handle, "pqcrystals_dilithium5_ref_verify");
  int res = verify(sig, siglen, msg, msglen, ctx, ctxlen, pk);
  dlclose(handle);
  return res;
}
