#include <dlfcn.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>


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



void CC_MLDSA_44_sign(uint8_t *sig, size_t siglen, const uint8_t *msg, size_t msglen, const uint8_t *ctx, size_t ctxlen, const uint8_t *sk, size_t sklen) {
  void *handle = get_lib_handle("ML-DSA-44-ref.so");
  void (*sign)(uint8_t *, size_t *, const uint8_t *, const size_t, const uint8_t *, const size_t, const uint8_t *);
  sign = get_func(handle, "pqcrystals_dilithium2_ref_signature");
  size_t r_siglen;
  sign(sig, &r_siglen, msg, msglen, ctx, ctxlen, sk);
  dlclose(handle);
}

void CC_MLDSA_65_sign(uint8_t *sig, size_t siglen, const uint8_t *msg, size_t msglen, const uint8_t *ctx, size_t ctxlen, const uint8_t *sk, size_t sklen) {
  void *handle = get_lib_handle("ML-DSA-65-ref.so");
  void (*sign)(uint8_t *, size_t *, const uint8_t *, const size_t, const uint8_t *, const size_t, const uint8_t *);
  sign = get_func(handle, "pqcrystals_dilithium3_ref_signature");
  size_t r_siglen;
  sign(sig, &r_siglen, msg, msglen, ctx, ctxlen, sk);
  dlclose(handle);
}

void CC_MLDSA_87_sign(uint8_t *sig, size_t siglen, const uint8_t *msg, size_t msglen, const uint8_t *ctx, size_t ctxlen, const uint8_t *sk, size_t sklen) {
  void *handle = get_lib_handle("ML-DSA-87-ref.so");
  void (*sign)(uint8_t *, size_t *, const uint8_t *, const size_t, const uint8_t *, const size_t, const uint8_t *);
  sign = get_func(handle, "pqcrystals_dilithium5_ref_signature");
  size_t r_siglen;
  sign(sig, &r_siglen, msg, msglen, ctx, ctxlen, sk);
  dlclose(handle);
}

/* VERIFY */


int CC_MLDSA_44_verify(const uint8_t *sig, size_t siglen, const uint8_t *msg, size_t msglen, const uint8_t *ctx, size_t ctxlen, const uint8_t *pk, size_t pklen) {
  void *handle = get_lib_handle("ML-DSA-44-ref.so");
  int (*verify)(const uint8_t *, size_t, const uint8_t *, const size_t, const uint8_t *, const size_t, const uint8_t *);
  verify = get_func(handle, "pqcrystals_dilithium2_ref_verify");
  int res = verify(sig, siglen, msg, msglen, ctx, ctxlen, pk);
  dlclose(handle);
  return res;
}

int CC_MLDSA_65_verify(const uint8_t *sig, size_t siglen, const uint8_t *msg, size_t msglen, const uint8_t *ctx, size_t ctxlen, const uint8_t *pk, size_t pklen) {
  void *handle = get_lib_handle("ML-DSA-65-ref.so");
  int (*verify)(const uint8_t *, size_t, const uint8_t *, const size_t, const uint8_t *, const size_t, const uint8_t *);
  verify = get_func(handle, "pqcrystals_dilithium3_ref_verify");
  int res = verify(sig, siglen, msg, msglen, ctx, ctxlen, pk);
  dlclose(handle);
  return res;
}

int CC_MLDSA_87_verify(const uint8_t *sig, size_t siglen, const uint8_t *msg, size_t msglen, const uint8_t *ctx, size_t ctxlen, const uint8_t *pk, size_t pklen) {
  void *handle = get_lib_handle("ML-DSA-87-ref.so");
  int (*verify)(const uint8_t *, size_t, const uint8_t *, const size_t, const uint8_t *, const size_t, const uint8_t *);
  verify = get_func(handle, "pqcrystals_dilithium5_ref_verify");
  int res = verify(sig, siglen, msg, msglen, ctx, ctxlen, pk);
  dlclose(handle);
  return res;
}
