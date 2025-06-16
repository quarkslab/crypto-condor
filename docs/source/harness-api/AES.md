# AES harness

## Test encryption

To test a function that encrypts with AES, the harness function must:

- follow the naming convention;
- conform to the function signature.

### Naming convention

```
CC_AES_<mode>_encrypt
```

Where `mode` is one of: `ECB`, `CBC`, `CBCPKCS7`, `CTR`, `CFB8`, `CFB128`.

This tests all key lengths. A specific one can be indicated:

```
CC_AES_<mode>_<length>_encrypt
```

Where `length` is one of `128`, `192`, or `256`.

### Function signature

```{eval-rst}
.. c:function:: int AES_encrypt(\
    uint8_t *ciphertext, size_t ciphertext_size,\
    const uint8_t *plaintext, size_t plaintext_size,\
    const uint8_t *key, size_t key_size,\
    const uint8_t *iv, size_t iv_size)

    Encrypts a plaintext with AES.

    :param ciphertext: **[Out]** An allocated buffer to return the resulting ciphertext.
    :param ciphertext_size: **[In]** The size of ``ciphertext`` in bytes.
    :param plaintext: **[In]** The plaintext to encrypt.
    :param plaintext_size: **[In]** The size of ``plaintext`` in bytes.
    :param key: **[In]** The symmetric key to use.
    :param key_size: **[In]** The size of ``key`` in bytes. Passed even when specifying the key size.
    :param iv: **[In]** The IV to use. Not used for ECB mode.
    :param iv_size: **[In]** The size of ``iv`` in bytes. 0 if the IV is not used.
    :returns: A status value.
    :retval 1: Operation successful.
    :retval 0: An error occurred.
```

### Example

```{literalinclude} ../../../tests/harness/AES_openssl_encrypt.harness.c
:language: c
```

Compile with:

```bash
gcc -fPIC -shared -o AES_openssl_encrypt.so AES_openssl_encrypt.c -lssl -lcrypto
```

Then test with:

```bash
crypto-condor-cli test harness AES_openssl_encrypt.so
```

## Test authenticated encryption

To test a function that encrypts with an AEAD mode, the harness function must:

- follow the naming convention;
- conform to the function signature.

### Naming convention

```
CC_AES_<mode>_encrypt
```

Where `mode` is one of: `CCM`, `GCM`.

This tests all key lengths. A specific one can be indicated:

```
CC_AES_<mode>_<length>_encrypt
```

Where `length` is one of `128`, `192`, or `256`.

### Function signature

```{eval-rst}
.. c:function:: int AES_encrypt_aead(\
    uint8_t *ciphertext, size_t ciphertext_size,\
    uint8_t *mac, size_t mac_size,\
    const uint8_t *plaintext, size_t plaintext_size,\
    const uint8_t *key, size_t key_size,\
    const uint8_t *iv, size_t iv_size,\
    const uint8_t *aad, size_t aad_size)

    Encrypts a plaintext with AES and an AEAD mode of operation.

    :param ciphertext: **[Out]** An allocated buffer to return the resulting ciphertext.
    :param ciphertext_size: **[In]** The size of ``ciphertext`` in bytes.
    :param mac: **[Out]** An allocated buffer to return the resulting MAC tag.
    :param mac_size: **[In]** The size of ``mac`` in bytes.
    :param plaintext: **[In]** The plaintext to encrypt.
    :param plaintext_size: **[In]** The size of ``plaintext`` in bytes.
    :param key: **[In]** The symmetric key to use.
    :param key_size: **[In]** The size of ``key`` in bytes. Passed even when specifying the key size.
    :param iv: **[In]** The IV to use. Not used for ECB mode.
    :param iv_size: **[In]** The size of ``iv`` in bytes. 0 if the IV is not used.
    :returns: A status value.
    :retval 1: Operation successful.
    :retval 0: An error occurred.
```

### Example

```{literalinclude} ../../../tests/harness/AES_openssl_encrypt_aead.harness.c
:language: c
```

Compile with:

```bash
gcc -fPIC -shared -o AES_openssl_encrypt_aead.so AES_openssl_encrypt_aead.c -lssl -lcrypto
```

Then test with:

```bash
crypto-condor-cli test harness AES_openssl_encrypt_aead.so
```

## Test decryption

To test a function that decrypts with AES, the harness function must:

- follow the naming convention;
- conform to the function signature.

### Naming convention

```
CC_AES_<mode>_decrypt
```

Where `mode` is one of: `CCM`, `GCM`.

This tests all key lengths. A specific one can be indicated:

```
CC_AES_<mode>_<length>_decrypt
```

Where `length` is one of `128`, `192`, or `256`.

### Function signature

```{eval-rst}
.. c:function:: int AES_decrypt(\
    uint8_t *plaintext, size_t plaintext_size,\
    const uint8_t *ciphertext, size_t ciphertext_size,\
    const uint8_t *key, size_t key_size,\
    const uint8_t *iv, size_t iv_size)

    Decrypts a ciphertext with AES.

    :param plaintext: **[Out]** An allocated buffer to return the resulting plaintext.
    :param plaintext_size: **[In]** The size of ``plaintext`` in bytes.
    :param ciphertext: **[In]** The ciphertext to decrypt.
    :param ciphertext_size: **[In]** The size of ``ciphertext`` in bytes.
    :param key: **[In]** The symmetric key to use.
    :param key_size: **[In]** The size of ``key`` in bytes. Passed even when specifying the key size.
    :param iv: **[In]** The IV to use. Not used for ECB mode.
    :param iv_size: **[In]** The size of ``iv`` in bytes. 0 if the IV is not used.
    :returns: The actual size of the (unpadded) plaintext, or -1 if an error occurred.
```

### Example

```{literalinclude} ../../../tests/harness/AES_openssl_decrypt.harness.c
:language: c
```

Compile with:

```bash
gcc -fPIC -shared -o AES_openssl_decrypt.so AES_openssl_decrypt.c -lssl -lcrypto
```

Then test with:

```bash
crypto-condor-cli test harness AES_openssl_decrypt.so
```

## Test authenticated decryption

To test a function that decrypts with an AEAD mode, the harness function must:

- follow the naming convention;
- conform to the function signature.

### Naming convention

```
CC_AES_<mode>_decrypt
```

Where `mode` is one of: `CCM`, `GCM`.

This tests all key lengths. A specific one can be indicated:

```
CC_AES_<mode>_<length>_decrypt
```

Where `length` is one of `128`, `192`, or `256`.

### Function signature

```{eval-rst}
.. c:function:: int AES_decrypt_aead(\
    uint8_t *plaintext, size_t plaintext_size,\
    const uint8_t *ciphertext, size_t ciphertext_size,\
    const uint8_t *mac, size_t mac_size,\
    const uint8_t *key, size_t key_size,\
    const uint8_t *iv, size_t iv_size,\
    const uint8_t *aad, size_t aad_size)

    Decrypts a ciphertext with AES and an AEAD mode of operation.

    :param plaintext: **[Out]** An allocated buffer to return the resulting plaintext.
    :param plaintext_size: **[In]** The size of ``plaintext`` in bytes.
    :param ciphertext: **[In]** The ciphertext to decrypt.
    :param ciphertext_size: **[In]** The size of ``ciphertext`` in bytes.
    :param mac: **[In]** The MAC tag to verify.
    :param mac_size: **[In]** The size of ``mac`` in bytes.
    :param key: **[In]** The symmetric key to use.
    :param key_size: **[In]** The size of ``key`` in bytes. Passed even when specifying the key size.
    :param iv: **[In]** The IV to use. Not used for ECB mode.
    :param iv_size: **[In]** The size of ``iv`` in bytes. 0 if the IV is not used.
    :returns: A status value.
    :retval 1: Operation successful.
    :retval 0: An error occurred.
    :retval -1: The MAC tag is invalid.
```

### Example

```{literalinclude} ../../../tests/harness/AES_openssl_decrypt_aead.harness.c
:language: c
```

Compile with:

```bash
gcc -fPIC -shared -o AES_openssl_decrypt_aead.so AES_openssl_decrypt_aead.c -lssl -lcrypto
```

Then test with:

```bash
crypto-condor-cli test harness AES_openssl_decrypt_aead.so
```

