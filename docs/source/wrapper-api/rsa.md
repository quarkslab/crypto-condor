# RSA Python wrapper

```{currentmodule} crypto_condor.primitives.RSAES
```

Python RSA wrappers can be used to test RSA decryption.

## Decryption with PKCS#1 v1.5 padding

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

## Decryption with OAEP padding

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

## Signing with PKCS#1 v1.5 padding

```{currentmodule} crypto_condor.primitives.RSASSA
```

To test RSA signing with PKCS#1 v1.5 padding, the function must follow the
naming convention and implement the `Sign` protocol.

### Naming convention

```
CC_RSASSA_sign_pkcs_<hash algorithm>
```

Where:

- `hash algorithm` is one of: `sha224`, `sha256`, `sha384`, `sha512`, `sha512224`, `sha512256`, `sha3224`, `sha3256`, `sha3384`, `sha3512`.

### Protocol

```{eval-rst}
.. autoprotocol:: Sign
    :noindex:
```

## Verifying RSA-PKCS1-v1.5 signatures

To test RSA signature verification with PKCS#1 v1.5 padding, the function must
follow the naming convention and implement the `VerifyPkcs` protocol.

### Naming convention

```
CC_RSASSA_verify_pkcs_<hash algorithm>
```

Where:

- `hash algorithm` is one of: `sha1`, `sha224`, `sha256`, `sha384`, `sha512`.

### Protocol

```{eval-rst}
.. autoprotocol:: VerifyPkcs
    :noindex:
```

## Signing with PSS padding

To test RSA signing with PSS padding, the function must follow the naming
convention and implement the `Sign` protocol.

### Naming convention

```
CC_RSASSA_sign_pss_<hash algorithm>
```

Where:

- `hash algorithm` is one of: `sha1`, `sha256`, `sha512`, `sha512256`.

### Protocol

```{eval-rst}
.. autoprotocol:: Sign
    :noindex:
```

## Verifying RSA-PSS signatures

To test RSA signature verification with PSS padding, the function must follow
the naming convention and implement the `VerifyPss` protocol.

### Naming convention

```
CC_RSASSA_verify_pss_<hash algorithm>
```

Where:

- `hash algorithm` is one of: `sha1`, `sha256`, `sha512`, `sha512256`.

### Protocol

```{eval-rst}
.. autoprotocol:: VerifyPss
    :noindex:
```

## Decryption example

```{literalinclude} ../../../crypto_condor/resources/wrappers/RSAES/Python-examples/1/rsaes_wrapper_example.py
```

## Signing and verifying example

```{literalinclude} ../../../crypto_condor/resources/wrappers/RSASSA/Python-examples/1/rsassa_wrapper_example.py
```
