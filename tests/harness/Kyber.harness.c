#include <dlfcn.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

void *get_lib_handle(const char lib_name[]) {
  void *handle;
  char libdir[PATH_MAX];

  snprintf(libdir, PATH_MAX, "%s/%s/%s", getenv("HOME"),
           ".local/share/crypto-condor/Kyber", lib_name);
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

void CC_Kyber_512_encapsulate(uint8_t *ct, size_t ct_sz, uint8_t *ss,
                              size_t ss_sz, const uint8_t *pk, size_t pk_sz) {

  void *handle = get_lib_handle("libpqcrystals_kyber512_ref.so");
  void (*enc)(uint8_t *, uint8_t *, const uint8_t *);
  enc = get_func(handle, "pqcrystals_kyber512_ref_enc");
  enc(ct, ss, pk);
  dlclose(handle);
}
void CC_Kyber_768_encapsulate(uint8_t *ct, size_t ct_sz, uint8_t *ss,
                              size_t ss_sz, const uint8_t *pk, size_t pk_sz) {

  void *handle = get_lib_handle("libpqcrystals_kyber768_ref.so");
  void (*enc)(uint8_t *, uint8_t *, const uint8_t *);
  enc = get_func(handle, "pqcrystals_kyber768_ref_enc");
  enc(ct, ss, pk);
  dlclose(handle);
}
void CC_Kyber_1024_encapsulate(uint8_t *ct, size_t ct_sz, uint8_t *ss,
                               size_t ss_sz, const uint8_t *pk, size_t pk_sz) {

  void *handle = get_lib_handle("libpqcrystals_kyber1024_ref.so");
  void (*enc)(uint8_t *, uint8_t *, const uint8_t *);
  enc = get_func(handle, "pqcrystals_kyber1024_ref_enc");
  enc(ct, ss, pk);
  dlclose(handle);
}
void CC_Kyber_512_90s_encapsulate(uint8_t *ct, size_t ct_sz, uint8_t *ss,
                                  size_t ss_sz, const uint8_t *pk,
                                  size_t pk_sz) {

  void *handle = get_lib_handle("libpqcrystals_kyber512-90s_ref.so");
  void (*enc)(uint8_t *, uint8_t *, const uint8_t *);
  enc = get_func(handle, "pqcrystals_kyber512_90s_ref_enc");
  enc(ct, ss, pk);
  dlclose(handle);
}
void CC_Kyber_768_90s_encapsulate(uint8_t *ct, size_t ct_sz, uint8_t *ss,
                                  size_t ss_sz, const uint8_t *pk,
                                  size_t pk_sz) {

  void *handle = get_lib_handle("libpqcrystals_kyber768-90s_ref.so");
  void (*enc)(uint8_t *, uint8_t *, const uint8_t *);
  enc = get_func(handle, "pqcrystals_kyber768_90s_ref_enc");
  enc(ct, ss, pk);
  dlclose(handle);
}
void CC_Kyber_1024_90s_encapsulate(uint8_t *ct, size_t ct_sz, uint8_t *ss,
                                   size_t ss_sz, const uint8_t *pk,
                                   size_t pk_sz) {

  void *handle = get_lib_handle("libpqcrystals_kyber1024-90s_ref.so");
  void (*enc)(uint8_t *, uint8_t *, const uint8_t *);
  enc = get_func(handle, "pqcrystals_kyber1024_90s_ref_enc");
  enc(ct, ss, pk);
  dlclose(handle);
}

/* DECAPSULATE */

void CC_Kyber_512_decapsulate(uint8_t *ss, size_t ss_sz, const uint8_t *ct,
                              size_t ct_sz, const uint8_t *sk, size_t sk_sz) {

  void *handle = get_lib_handle("libpqcrystals_kyber512_ref.so");
  void (*dec)(uint8_t *, const uint8_t *, const uint8_t *);
  dec = get_func(handle, "pqcrystals_kyber512_ref_dec");
  dec(ss, ct, sk);
  dlclose(handle);
}
void CC_Kyber_768_decapsulate(uint8_t *ss, size_t ss_sz, const uint8_t *ct,
                              size_t ct_sz, const uint8_t *sk, size_t sk_sz) {

  void *handle = get_lib_handle("libpqcrystals_kyber768_ref.so");
  void (*dec)(uint8_t *, const uint8_t *, const uint8_t *);
  dec = get_func(handle, "pqcrystals_kyber768_ref_dec");
  dec(ss, ct, sk);
  dlclose(handle);
}
void CC_Kyber_1024_decapsulate(uint8_t *ss, size_t ss_sz, const uint8_t *ct,
                               size_t ct_sz, const uint8_t *sk, size_t sk_sz) {

  void *handle = get_lib_handle("libpqcrystals_kyber1024_ref.so");
  void (*dec)(uint8_t *, const uint8_t *, const uint8_t *);
  dec = get_func(handle, "pqcrystals_kyber1024_ref_dec");
  dec(ss, ct, sk);
  dlclose(handle);
}
void CC_Kyber_512_90s_decapsulate(uint8_t *ss, size_t ss_sz, const uint8_t *ct,
                                  size_t ct_sz, const uint8_t *sk,
                                  size_t sk_sz) {

  void *handle = get_lib_handle("libpqcrystals_kyber512-90s_ref.so");
  void (*dec)(uint8_t *, const uint8_t *, const uint8_t *);
  dec = get_func(handle, "pqcrystals_kyber512_90s_ref_dec");
  dec(ss, ct, sk);
  dlclose(handle);
}
void CC_Kyber_768_90s_decapsulate(uint8_t *ss, size_t ss_sz, const uint8_t *ct,
                                  size_t ct_sz, const uint8_t *sk,
                                  size_t sk_sz) {

  void *handle = get_lib_handle("libpqcrystals_kyber768-90s_ref.so");
  void (*dec)(uint8_t *, const uint8_t *, const uint8_t *);
  dec = get_func(handle, "pqcrystals_kyber768_90s_ref_dec");
  dec(ss, ct, sk);
  dlclose(handle);
}
void CC_Kyber_1024_90s_decapsulate(uint8_t *ss, size_t ss_sz, const uint8_t *ct,
                                   size_t ct_sz, const uint8_t *sk,
                                   size_t sk_sz) {

  void *handle = get_lib_handle("libpqcrystals_kyber1024-90s_ref.so");
  void (*dec)(uint8_t *, const uint8_t *, const uint8_t *);
  dec = get_func(handle, "pqcrystals_kyber1024_90s_ref_dec");
  dec(ss, ct, sk);
  dlclose(handle);
}
