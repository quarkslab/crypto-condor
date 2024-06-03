#include <dlfcn.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

void *get_lib_handle(const char lib_name[]) {
  void *handle;
  char libdir[PATH_MAX];

  snprintf(libdir, PATH_MAX, "%s/%s/%s", getenv("HOME"),
           ".local/share/crypto-condor/AES", lib_name);
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

void CC_AES_ECB_encrypt(uint8_t *buffer, size_t buffer_size, const uint8_t *key,
                        size_t key_size, const uint8_t *iv, size_t iv_size) {
  struct AES_ctx ctx;
  void *handle = get_lib_handle("aes.so");
  void (*init)(struct AES_ctx *, const uint8_t *, size_t);
  void (*enc)(const struct AES_ctx *, uint8_t *, size_t);

  init = get_func(handle, "AES_init_ctx");
  enc = get_func(handle, "AES_ECB_encrypt_buffer");

  init(&ctx, key, key_size);
  enc(&ctx, buffer, buffer_size);
}

void CC_AES_ECB_decrypt(uint8_t *buffer, size_t buffer_size, const uint8_t *key,
                        size_t key_size, const uint8_t *iv, size_t iv_size) {
  struct AES_ctx ctx;
  void *handle = get_lib_handle("aes.so");
  void (*init)(struct AES_ctx *, const uint8_t *, size_t);
  void (*dec)(const struct AES_ctx *, uint8_t *, size_t);

  init = get_func(handle, "AES_init_ctx");
  dec = get_func(handle, "AES_ECB_decrypt_buffer");

  init(&ctx, key, key_size);
  dec(&ctx, buffer, buffer_size);
}

void CC_AES_CBC_encrypt(uint8_t *buffer, size_t buffer_size, const uint8_t *key,
                        size_t key_size, const uint8_t *iv, size_t iv_size) {
  struct AES_ctx ctx;
  void *handle = get_lib_handle("aes.so");
  void (*init)(struct AES_ctx *, const uint8_t *, size_t, const uint8_t *);
  void (*enc)(const struct AES_ctx *, uint8_t *, size_t);

  init = get_func(handle, "AES_init_ctx_iv");
  enc = get_func(handle, "AES_CBC_encrypt_buffer");

  init(&ctx, key, key_size, iv);
  enc(&ctx, buffer, buffer_size);
}

void CC_AES_CBC_decrypt(uint8_t *buffer, size_t buffer_size, const uint8_t *key,
                        size_t key_size, const uint8_t *iv, size_t iv_size) {
  struct AES_ctx ctx;
  void *handle = get_lib_handle("aes.so");
  void (*init)(struct AES_ctx *, const uint8_t *, size_t, const uint8_t *);
  void (*dec)(const struct AES_ctx *, uint8_t *, size_t);

  init = get_func(handle, "AES_init_ctx_iv");
  dec = get_func(handle, "AES_CBC_decrypt_buffer");

  init(&ctx, key, key_size, iv);
  dec(&ctx, buffer, buffer_size);
}

void CC_AES_CTR_encrypt(uint8_t *buffer, size_t buffer_size, const uint8_t *key,
                        size_t key_size, const uint8_t *iv, size_t iv_size) {
  struct AES_ctx ctx;
  void *handle = get_lib_handle("aes.so");
  void (*init)(struct AES_ctx *, const uint8_t *, size_t, const uint8_t *);
  void (*enc)(const struct AES_ctx *, uint8_t *, size_t);

  init = get_func(handle, "AES_init_ctx_iv");
  enc = get_func(handle, "AES_CTR_xcrypt_buffer");

  init(&ctx, key, key_size, iv);
  enc(&ctx, buffer, buffer_size);
}

void CC_AES_CTR_decrypt(uint8_t *buffer, size_t buffer_size, const uint8_t *key,
                        size_t key_size, const uint8_t *iv, size_t iv_size) {
  struct AES_ctx ctx;
  void *handle = get_lib_handle("aes.so");
  void (*init)(struct AES_ctx *, const uint8_t *, size_t, const uint8_t *);
  void (*dec)(const struct AES_ctx *, uint8_t *, size_t);

  init = get_func(handle, "AES_init_ctx_iv");
  dec = get_func(handle, "AES_CTR_xcrypt_buffer");

  init(&ctx, key, key_size, iv);
  dec(&ctx, buffer, buffer_size);
}

void CC_AES_CFB8_encrypt(uint8_t *buffer, size_t buffer_size,
                         const uint8_t *key, size_t key_size, const uint8_t *iv,
                         size_t iv_size) {
  struct AES_ctx ctx;
  void *handle = get_lib_handle("aes.so");
  void (*init)(struct AES_ctx *, const uint8_t *, size_t, const uint8_t *);
  void (*enc)(const struct AES_ctx *, uint8_t *, size_t, size_t);

  init = get_func(handle, "AES_init_ctx_iv");
  enc = get_func(handle, "AES_CFB_encrypt_buffer");

  init(&ctx, key, key_size, iv);
  enc(&ctx, buffer, buffer_size, 8);
}

void CC_AES_CFB8_decrypt(uint8_t *buffer, size_t buffer_size,
                         const uint8_t *key, size_t key_size, const uint8_t *iv,
                         size_t iv_size) {
  struct AES_ctx ctx;
  void *handle = get_lib_handle("aes.so");
  void (*init)(struct AES_ctx *, const uint8_t *, size_t, const uint8_t *);
  void (*dec)(const struct AES_ctx *, uint8_t *, size_t, size_t);

  init = get_func(handle, "AES_init_ctx_iv");
  dec = get_func(handle, "AES_CFB_decrypt_buffer");

  init(&ctx, key, key_size, iv);
  dec(&ctx, buffer, buffer_size, 8);
}

void CC_AES_CFB128_encrypt(uint8_t *buffer, size_t buffer_size,
                           const uint8_t *key, size_t key_size,
                           const uint8_t *iv, size_t iv_size) {
  struct AES_ctx ctx;
  void *handle = get_lib_handle("aes.so");
  void (*init)(struct AES_ctx *, const uint8_t *, size_t, const uint8_t *);
  void (*enc)(const struct AES_ctx *, uint8_t *, size_t, size_t);

  init = get_func(handle, "AES_init_ctx_iv");
  enc = get_func(handle, "AES_CFB_encrypt_buffer");

  init(&ctx, key, key_size, iv);
  enc(&ctx, buffer, buffer_size, 128);
}

void CC_AES_CFB128_decrypt(uint8_t *buffer, size_t buffer_size,
                           const uint8_t *key, size_t key_size,
                           const uint8_t *iv, size_t iv_size) {
  struct AES_ctx ctx;
  void *handle = get_lib_handle("aes.so");
  void (*init)(struct AES_ctx *, const uint8_t *, size_t, const uint8_t *);
  void (*dec)(const struct AES_ctx *, uint8_t *, size_t, size_t);

  init = get_func(handle, "AES_init_ctx_iv");
  dec = get_func(handle, "AES_CFB_decrypt_buffer");

  init(&ctx, key, key_size, iv);
  dec(&ctx, buffer, buffer_size, 128);
}
