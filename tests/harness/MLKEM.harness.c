#include <dlfcn.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

void *get_lib_handle(const char lib_name[]) {
  void *handle;
  char libdir[PATH_MAX];

  snprintf(libdir, PATH_MAX, "%s/%s/%s", getenv("HOME"),
           ".local/share/crypto-condor/MLKEM", lib_name);
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

void CC_MLKEM_512_encaps(uint8_t *ct, size_t ct_sz, uint8_t *ss,
                              size_t ss_sz, const uint8_t *pk, size_t pk_sz) {

  void *handle = get_lib_handle("ML-KEM-512-ref.so");
  void (*enc)(uint8_t *, uint8_t *, const uint8_t *);
  enc = get_func(handle, "pqcrystals_kyber512_ref_enc");
  enc(ct, ss, pk);
  dlclose(handle);
}
void CC_MLKEM_768_encaps(uint8_t *ct, size_t ct_sz, uint8_t *ss,
                              size_t ss_sz, const uint8_t *pk, size_t pk_sz) {

  void *handle = get_lib_handle("ML-KEM-768-ref.so");
  void (*enc)(uint8_t *, uint8_t *, const uint8_t *);
  enc = get_func(handle, "pqcrystals_kyber768_ref_enc");
  enc(ct, ss, pk);
  dlclose(handle);
}
void CC_MLKEM_1024_encaps(uint8_t *ct, size_t ct_sz, uint8_t *ss,
                               size_t ss_sz, const uint8_t *pk, size_t pk_sz) {

  void *handle = get_lib_handle("ML-KEM-1024-ref.so");
  void (*enc)(uint8_t *, uint8_t *, const uint8_t *);
  enc = get_func(handle, "pqcrystals_kyber1024_ref_enc");
  enc(ct, ss, pk);
  dlclose(handle);
}

/* DECAPSULATE */

void CC_MLKEM_512_decaps(uint8_t *ss, size_t ss_sz, const uint8_t *ct,
                              size_t ct_sz, const uint8_t *sk, size_t sk_sz) {

  void *handle = get_lib_handle("ML-KEM-512-ref.so");
  void (*dec)(uint8_t *, const uint8_t *, const uint8_t *);
  dec = get_func(handle, "pqcrystals_kyber512_ref_dec");
  dec(ss, ct, sk);
  dlclose(handle);
}
void CC_MLKEM_768_decaps(uint8_t *ss, size_t ss_sz, const uint8_t *ct,
                              size_t ct_sz, const uint8_t *sk, size_t sk_sz) {

  void *handle = get_lib_handle("ML-KEM-768-ref.so");
  void (*dec)(uint8_t *, const uint8_t *, const uint8_t *);
  dec = get_func(handle, "pqcrystals_kyber768_ref_dec");
  dec(ss, ct, sk);
  dlclose(handle);
}
void CC_MLKEM_1024_decaps(uint8_t *ss, size_t ss_sz, const uint8_t *ct,
                               size_t ct_sz, const uint8_t *sk, size_t sk_sz) {

  void *handle = get_lib_handle("ML-KEM-1024-ref.so");
  void (*dec)(uint8_t *, const uint8_t *, const uint8_t *);
  dec = get_func(handle, "pqcrystals_kyber1024_ref_dec");
  dec(ss, ct, sk);
  dlclose(handle);
}
