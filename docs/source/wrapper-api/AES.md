# AES wrapper

```{currentmodule} crypto_condor.primitives.AES
```

Python AES wrappers can be used to test both encryption and decryption of all supported
modes of operation.

To get a template using the CLI, run:

```bash
crypto-condor-cli get-wrapper AES --language Python
```

To get a practical example, run:

```bash
crypto-condor-cli get-wrapper AES --language Python --example 1
````

## Encrypt

To test an implementation of AES encryption, the function must:

- follow the naming convention;
- implement the `Encrypt` protocol.

### Naming convention

```
CC_AES_<mode>_encrypt
```

Where `mode` is one of: `ECB`, `CBC`, `CBCPKCS7`, `CTR`, `CFB8`, `CFB128`, `GCM`, `CCM`.

This tests all key lengths. A specific one can be indicated:

```
CC_AES_<mode>_<length>_encrypt
```

Where `length` is one of `128`, `192`, or `256`.

### Protocol

```{eval-rst}
.. autoprotocol:: Encrypt
    :noindex:
```

## Decrypt

To test an implementation of AES decryption, the function must:

- follow the naming convention;
- implement the `Decrypt` protocol.

### Naming convention

```
CC_AES_<mode>_decrypt
```

Where `mode` is one of: `ECB`, `CBC`, `CBCPKCS7`, `CTR`, `CFB8`, `CFB128`, `GCM`, `CCM`.

This tests all key lengths. A specific one can be indicated:

```
CC_AES_<mode>_<key length>_decrypt
```

Where `length` is one of `128`, `192`, or `256`.

### Protocol

```{eval-rst}
.. autoprotocol:: Decrypt
    :noindex:
```

## Example

```{literalinclude} ../../../crypto_condor/resources/wrappers/AES/Python-examples/1/aes_wrapper_example.py
```
