#include <dlfcn.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

void CC_Dilithium_2_sign(uint8_t *sig, size_t siglen, const uint8_t *m,
                         size_t mlen, const uint8_t *sk, size_t sklen) {
  void *handle;
  char libdir[PATH_MAX];

  snprintf(libdir, PATH_MAX, "%s/%s", getenv("HOME"),
           ".local/share/crypto-condor/Dilithium/dilithium/ref/"
           "libpqcrystals_dilithium2_ref.so");
  handle = dlopen(libdir, RTLD_LAZY);
  if (!handle) {
    fprintf(stderr, "dlopen error: %s\n", dlerror());
    exit(1);
  }

  void (*sign)(uint8_t *, size_t *, const uint8_t *, const size_t,
               const uint8_t *);
  sign = dlsym(handle, "pqcrystals_dilithium2_ref_signature");
  if (!sign) {
    fprintf(stderr, "dlsym error: %s\n", dlerror());
    dlclose(handle);
    exit(1);
  }

  size_t r_siglen;
  sign(sig, &r_siglen, m, mlen, sk);
  dlclose(handle);
}

void CC_Dilithium_3_sign(uint8_t *sig, size_t siglen, const uint8_t *m,
                         size_t mlen, const uint8_t *sk, size_t sklen) {
  void *handle;
  char libdir[PATH_MAX];

  snprintf(libdir, PATH_MAX, "%s/%s", getenv("HOME"),
           ".local/share/crypto-condor/Dilithium/dilithium/ref/"
           "libpqcrystals_dilithium3_ref.so");
  handle = dlopen(libdir, RTLD_LAZY);
  if (!handle) {
    fprintf(stderr, "dlopen error: %s\n", dlerror());
    exit(1);
  }

  void (*sign)(uint8_t *, size_t *, const uint8_t *, const size_t,
               const uint8_t *);
  sign = dlsym(handle, "pqcrystals_dilithium3_ref_signature");
  if (!sign) {
    fprintf(stderr, "dlsym error: %s\n", dlerror());
    dlclose(handle);
    exit(1);
  }

  size_t r_siglen;
  sign(sig, &r_siglen, m, mlen, sk);
  dlclose(handle);
}

void CC_Dilithium_5_sign(uint8_t *sig, size_t siglen, const uint8_t *m,
                         size_t mlen, const uint8_t *sk, size_t sklen) {
  void *handle;
  char libdir[PATH_MAX];

  snprintf(libdir, PATH_MAX, "%s/%s", getenv("HOME"),
           ".local/share/crypto-condor/Dilithium/dilithium/ref/"
           "libpqcrystals_dilithium5_ref.so");
  handle = dlopen(libdir, RTLD_LAZY);
  if (!handle) {
    fprintf(stderr, "dlopen error: %s\n", dlerror());
    exit(1);
  }

  void (*sign)(uint8_t *, size_t *, const uint8_t *, const size_t,
               const uint8_t *);
  sign = dlsym(handle, "pqcrystals_dilithium5_ref_signature");
  if (!sign) {
    fprintf(stderr, "dlsym error: %s\n", dlerror());
    dlclose(handle);
    exit(1);
  }

  size_t r_siglen;
  sign(sig, &r_siglen, m, mlen, sk);
  dlclose(handle);
}

int CC_Dilithium_2_verify(const uint8_t *sig, size_t siglen, const uint8_t *m,
                          size_t mlen, const uint8_t *pk, size_t pklen) {
  void *handle;
  char libdir[PATH_MAX];

  snprintf(libdir, PATH_MAX, "%s/%s", getenv("HOME"),
           ".local/share/crypto-condor/Dilithium/dilithium/ref/"
           "libpqcrystals_dilithium2_ref.so");
  handle = dlopen(libdir, RTLD_LAZY);
  if (!handle) {
    fprintf(stderr, "dlopen error: %s\n", dlerror());
    exit(1);
  }

  int (*verify)(const uint8_t *, size_t, const uint8_t *, const size_t,
                const uint8_t *);
  verify = dlsym(handle, "pqcrystals_dilithium2_ref_verify");
  if (!verify) {
    fprintf(stderr, "dlsym error: %s\n", dlerror());
    dlclose(handle);
    exit(1);
  }

  int res = verify(sig, siglen, m, mlen, pk);
  dlclose(handle);
  return res;
}

int CC_Dilithium_3_verify(const uint8_t *sig, size_t siglen, const uint8_t *m,
                          size_t mlen, const uint8_t *pk, size_t pklen) {
  void *handle;
  char libdir[PATH_MAX];

  snprintf(libdir, PATH_MAX, "%s/%s", getenv("HOME"),
           ".local/share/crypto-condor/Dilithium/dilithium/ref/"
           "libpqcrystals_dilithium3_ref.so");
  handle = dlopen(libdir, RTLD_LAZY);
  if (!handle) {
    fprintf(stderr, "dlopen error: %s\n", dlerror());
    exit(1);
  }

  int (*verify)(const uint8_t *, size_t, const uint8_t *, const size_t,
                const uint8_t *);
  verify = dlsym(handle, "pqcrystals_dilithium3_ref_verify");
  if (!verify) {
    fprintf(stderr, "dlsym error: %s\n", dlerror());
    dlclose(handle);
    exit(1);
  }

  int res = verify(sig, siglen, m, mlen, pk);
  dlclose(handle);
  return res;
}

int CC_Dilithium_5_verify(const uint8_t *sig, size_t siglen, const uint8_t *m,
                          size_t mlen, const uint8_t *pk, size_t pklen) {
  void *handle;
  char libdir[PATH_MAX];

  snprintf(libdir, PATH_MAX, "%s/%s", getenv("HOME"),
           ".local/share/crypto-condor/Dilithium/dilithium/ref/"
           "libpqcrystals_dilithium5_ref.so");
  handle = dlopen(libdir, RTLD_LAZY);
  if (!handle) {
    fprintf(stderr, "dlopen error: %s\n", dlerror());
    exit(1);
  }

  int (*verify)(const uint8_t *, size_t, const uint8_t *, const size_t,
                const uint8_t *);
  verify = dlsym(handle, "pqcrystals_dilithium5_ref_verify");
  if (!verify) {
    fprintf(stderr, "dlsym error: %s\n", dlerror());
    dlclose(handle);
    exit(1);
  }

  int res = verify(sig, siglen, m, mlen, pk);
  dlclose(handle);
  return res;
}
