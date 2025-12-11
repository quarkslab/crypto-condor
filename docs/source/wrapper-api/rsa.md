# RSA Python wrapper

```{currentmodule} crypto_condor.primitives.RSAES
```

Python RSA wrappers can be used to test RSA decryption.

## Decryption with RSA-PKCS1-v1.5

To test RSA decryption with PKCS#1 v1.5 padding, the function must follow the
naming convention and implement the `DecryptPkcs` protocol.

### Naming convention

Decryption with PKCS does not accept any parameters, so the only function must
be called:

```
CC_RSAES_decrypt_pkcs
```

### Protocol

```{eval-rst}
.. autoprotocol:: DecryptPkcs
    :noindex:
```

## Decryption with RSA-OAEP

To test RSA decryption with OAEP padding, the function must follow the naming
convention and implement the `DecryptPkcs` protocol.

### Naming convention

```
CC_RSAES_decrypt_oaep_<hash algorithm>[_<mgf algorithm>]
```

Where:

- `hash algorithm` is one of: `sha1`, `sha224`, `sha256`, `sha384`, `sha512`.
- `mgf algorithm` is an optional parameter, can be one of: `sha1`, `sha224`, `sha256`, `sha384`, `sha512`.

Note that only the combinations in the form `hash A/hash A` and `hash A/SHA-1`
have test vectors.

### Protocol

```{eval-rst}
.. autoprotocol:: DecryptOaep
    :noindex:
```

## Decryption example

```{literalinclude} ../../../crypto_condor/resources/wrappers/RSAES/Python-examples/1/rsaes_wrapper_example.py
```
