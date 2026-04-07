# AES harness

```{currentmodule} crypto_condor.primitives.AES
```

```{versionchanged} FIXME(version)
The naming convention has changed from `CC_AES_<mode>_{en,de}crypt` to `CC_AES_{en,de}crypt_<mode>` to match the convention across primitives.
```

```{versionchanged} FIXME(version)
The naming convention has changed from `CC_AES_<mode>_<length>_{en,de}crypt` to `CC_AES_{en,de}crypt_<mode>_<length>` to match the convention across primitives.
```

```{versionchanged} FIXME(version)
A new convention was introduced for AEAD modes: `CC_AES_aead{en,de}crypt_<mode>` and `CC_AES_aead{en,de}crypt_<mode>_<length>`.
```

## Encryption

### Naming convention

```
CC_AES_encrypt_<mode>
```

Where `mode` is one of:

- `ECB`, `CBC`, `CBCPKCS7`, `CTR`, `CFB8`, `CFB128`.

This tests all key lengths. A specific one can be indicated:

```
CC_AES_encrypt_<mode>_<length>
```

Where `length` is one of:

- `128`, `192`, or `256`.

### Python harness

```{eval-rst}
.. autoprotocol:: crypto_condor.vectors.aes.Encrypt
    :noindex:
```

#### Example

```{literalinclude} ../../../tests/harness/AES/encrypt.py
```

### C harness

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

#### Example

```{literalinclude} ../../../tests/harness/AES/encrypt.c
:language: c
```

Compile with:

```bash
gcc -fPIC -shared -o aes_encrypt.so aes_encrypt.c -lssl -lcrypto
```

Then test with:

```bash
crypto-condor-cli test harness aes_encrypt.so
```

## Decryption

### Naming convention

```
CC_AES_decrypt_<mode>
```

Where `mode` is one of:

- `ECB`, `CBC`, `CBCPKCS7`, `CTR`, `CFB8`, `CFB128`.

This tests all key lengths. A specific one can be indicated:

```
CC_AES_decrypt_<mode>_<length>
```

Where `length` is one of:

- `128`, `192`, or `256`.

### Python harness

```{eval-rst}
.. autoprotocol:: crypto_condor.vectors.aes.Decrypt
    :noindex:
```

#### Example

```{literalinclude} ../../../tests/harness/AES/decrypt.py
```

### C harness

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

#### Example

```{literalinclude} ../../../tests/harness/AES/decrypt.c
:language: c
```

Compile with:

```bash
gcc -fPIC -shared -o aes_decrypt.so aes_decrypt.c -lssl -lcrypto
```

Then test with:

```bash
crypto-condor-cli test harness aes_decrypt.so
```

## Authenticated encryption

### Naming convention

```
CC_AES_aeadencrypt_<mode>
```

Where `mode` is one of:

- `CCM`, `GCM`.

This tests all key lengths. A specific one can be indicated:

```
CC_AES_encryptaead_<mode>_<length>
```

Where `length` is one of:

- `128`, `192`, or `256`.

### Python harness

```{eval-rst}
.. autoprotocol:: crypto_condor.vectors.aes.AeadEncrypt
    :noindex:
```

#### Example

```{literalinclude} ../../../tests/harness/AES/aeadencrypt.py
```

### C harness

```{eval-rst}
.. c:function:: int AES_aeadencrypt(\
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

#### Example

```{literalinclude} ../../../tests/harness/AES/aeadencrypt.c
:language: c
```

Compile with:

```bash
gcc -fPIC -shared -o aes_aeadencrypt.so aes_aeadencrypt.c -lssl -lcrypto
```

Then test with:

```bash
crypto-condor-cli test harness aes_aeadencrypt.so
```

## Authenticated decryption

### Naming convention

```
CC_AES_aeaddecrypt_<mode>
```

Where `mode` is one of:

- `CCM`, `GCM`.

This tests all key lengths. A specific one can be indicated:

```
CC_AES_aeaddecrypt_<mode>_<length>
```

Where `length` is one of:

- `128`, `192`, or `256`.

### Python harness

```{eval-rst}
.. autoprotocol:: crypto_condor.vectors.aes.AeadDecrypt
    :noindex:
```

#### Example

```{literalinclude} ../../../tests/harness/AES/aeaddecrypt.py
```

### C harness

```{eval-rst}
.. c:function:: int AES_aeaddecrypt(\
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

#### Example

```{literalinclude} ../../../tests/harness/AES/aeaddecrypt.c
:language: c
```

Compile with:

```bash
gcc -fPIC -shared -o aes_aeaddecrypt.so aes_aeaddecrypt.c -lssl -lcrypto
```

Then test with:

```bash
crypto-condor-cli test harness aes_aeaddecrypt.so
```
