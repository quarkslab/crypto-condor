# ChaCha20 Python wrapper

```{currentmodule} crypto_condor.primitives.ChaCha20
```

ChaCha20 and ChaCha20-Poly1305 encryption and decryption can be tested with Python
wrappers.

To get a template using the CLI, run:

```bash
crypto-condor-cli get-wrapper ChaCha20 --language Python
```

There is a practical example with PyCryptodome:

```bash
crypto-condor-cli get-wrapper ChaCha20 --language Python --example 1
```

## Encrypt

To test an implementation of ChaCha20 encryption, the function must:

- follow the naming convention;
- implement the `Encrypt` protocol.

### Naming convention

```
CC_ChaCha20_encrypt
```

### Protocol

```{eval-rst}
.. autoprotocol:: Encrypt
    :noindex:
```

## Decrypt

To test an implementation of ChaCha20 decryption, the function must:

- follow the naming convention;
- implement the `Decrypt` protocol.

### Naming convention

```
CC_ChaCha20_encrypt
```

### Protocol

```{eval-rst}
.. autoprotocol:: Decrypt
    :noindex:
```

## Encrypt with Poly1305

To test an implementation of ChaCha20-Poly1305 authenticated encryption, the function
must:

- follow the naming convention;
- implement the `EncryptPoly` protocol.

### Naming convention

```
CC_ChaCha20_encrypt_poly
```

### Protocol

```{eval-rst}
.. autoprotocol:: EncryptPoly
    :noindex:
```

## Decrypt

To test an implementation of ChaCha20-Poly1305 authenticated decryption, the function
must:

- follow the naming convention;
- implement the `DecryptPoly` protocol.

### Naming convention

```
CC_ChaCha20_decrypt_poly
```

### Protocol

```{eval-rst}
.. autoprotocol:: DecryptPoly
    :noindex:
```
