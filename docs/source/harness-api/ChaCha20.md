# ChaCha20

## Encrypt

To test a function that encrypts with ChaCha20 only, its name must conform to the following convention:

```
CC_ChaCha20_encrypt
```

Its signature must be:

```{eval-rst}
.. c:function:: int CC_ChaCha20_encrypt(\
    uint8_t *ciphertext, const uint8_t *plaintext, size_t text_size,\
    const uint8_t key[32], const uint8_t *nonce, size_t nonce_size,\
    uint32_t init_counter)

    :param ciphertext: **[Out]** An allocated buffer to return the resulting ciphertext.
    :param plaintext: **[In]** The plaintext to encrypt.
    :param text_size: **[In]** The size of the plaintext and ciphertext buffers.
    :param key: **[In]** The 32-byte key to use.
    :param nonce: **[In]** The nonce.
    :param nonce_size: **[In]** The size of the nonce in bytes.
    :param init_counter: **[In]** An absolute position within the keystream in bytes to seek before encrypting.
    :returns: A status value.
    :retval 1: OK.
    :retval 0: Failed to encrypt.
```

### Example

```{literalinclude} ../../../tests/harness/chacha20_openssl_encrypt.harness.c
:language: c
```

Compile with:

```bash
gcc -fPIC -shared -o chacha20_openssl_encrypt.so chacha20_openssl_encrypt.c -lssl -lcrypto
```

Then test with:

```bash
crypto-condor-cli test harness chacha20_openssl_encrypt.so
```

## Decrypt

To test a function that decrypts with ChaCha20 only, its name must conform to the following convention:

```
CC_ChaCha20_decrypt
```

Its signature must be:

```{eval-rst}
.. c:function:: void CC_ChaCha20_decrypt(\
    uint8_t *plaintext, const uint8_t *ciphertext, size_t text_size,\
    const uint8_t key[32], const uint8_t *nonce, size_t nonce_size,\
    uint64_t init_counter)

    :param plaintext: **[out]** an allocated buffer to return the resulting plaintext.
    :param ciphertext: **[in]** the ciphertext to decrypt.
    :param text_size: **[in]** the size of the plaintext and ciphertext buffers.
    :param key: **[In]** The 32-byte key to use.
    :param nonce: **[In]** The nonce.
    :param nonce_size: **[In]** The size of the nonce in bytes.
    :param init_counter: **[In]** An absolute position within the keystream in bytes to seek before encrypting.
    :returns: A status value.
    :retval 1: OK.
    :retval 0: Failed to decrypt.
```

### Example

```{literalinclude} ../../../tests/harness/chacha20_openssl_decrypt.harness.c
:language: c
```

Compile with:

```bash
gcc -fPIC -shared -o chacha20_openssl_decrypt.so chacha20_openssl_decrypt.c -lssl -lcrypto
```

Then test with:

```bash
crypto-condor-cli test harness chacha20_openssl_decrypt.so
```

## Encrypt with Poly1305

To test a function that encrypts with ChaCha20-Poly1305, its name must conform to the following convention:

```
CC_ChaCha20_encrypt_poly
```

Its signature must be:

```{eval-rst}
.. c:function:: int CC_ChaCha20_encrypt_poly(\
    uint8_t *ciphertext, uint8_t mac[16],\
    const uint8_t *plaintext, size_t text_size,\
    const uint8_t key[32], const uint8_t *nonce, size_t nonce_size,\
    const uint8_t *aad, size_t aad_size)

    :param ciphertext: **[Out]** An allocated buffer to return the resulting ciphertext.
    :param mac: **[Out]** buffer to store the resulting 16-byte MAC tag.
    :param plaintext: **[In]** The plaintext to encrypt.
    :param text_size: **[In]** The size of the plaintext and ciphertext buffers.
    :param key: **[In]** The 32-byte key to use.
    :param nonce: **[In]** The nonce.
    :param nonce_size: **[In]** The size of the nonce in bytes.
    :param aad: **[In]** The *optional* associated data. NULL if not used.
    :param aad_size: **[In]** The size of the associated data in bytes. 0 if not used.
    :returns: A status value.
    :retval 1: OK.
    :retval 0: Failed to encrypt.
```

### Example

```{literalinclude} ../../../tests/harness/chacha20_poly1305_openssl_encrypt.harness.c
:language: c
```

Compile with:

```bash
gcc -fPIC -shared -o chacha20_poly1305_openssl_encrypt.so chacha20_poly1305_openssl_encrypt.c -lssl -lcrypto
```

Then test with:

```bash
crypto-condor-cli test harness chacha20_poly1305_openssl_encrypt.so
```


## Decrypt with Poly1305

To test a function that decrypts with ChaCha20-Poly1305, its name must conform to the following convention:

```
CC_ChaCha20_poly1305_decrypt
```

Its signature must be:

```{eval-rst}
.. c:function:: int CC_ChaCha20_decrypt_poly(\
    uint8_t *plaintext, const uint8_t *ciphertext, size_t text_size,\
    const uint8_t key[32],\
    const uint8_t *nonce, size_t nonce_size,\
    const uint8_t *aad, size_t aad_size,\
    const uint8_t mac[16])

    :param plaintext: **[out]** an allocated buffer to return the resulting plaintext.
    :param ciphertext: **[in]** the ciphertext to decrypt.
    :param text_size: **[in]** the size of the plaintext and ciphertext buffers.
    :param key: **[In]** The 32-byte symmetric key.
    :param nonce: **[In]** The nonce.
    :param nonce_size: **[In]** The size of the nonce in bytes.
    :param aad: **[In]** The *optional* associated data. NULL if not used.
    :param aad_size: **[In]** The size of the associated data. 0 if not used.
    :param mac: **[In]** The 16-byte MAC tag to verify.
    :returns: A status value.
    :retval 1: OK.
    :retval 0: The MAC verification failed.
    :retval -1: Failed to decrypt.
```

### Example

```{literalinclude} ../../../tests/harness/chacha20_poly1305_openssl_decrypt.harness.c
:language: c
```

Compile with:

```bash
gcc -fPIC -shared -o chacha20_poly1305_openssl_decrypt.so chacha20_poly1305_openssl_decrypt.c -lssl -lcrypto
```

Then test with:

```bash
crypto-condor-cli test harness chacha20_poly1305_openssl_decrypt.so
```

