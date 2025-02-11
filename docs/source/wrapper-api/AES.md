# AES wrapper

Python AES wrappers can be used to test both encryption and decryption of all supported
modes of operation.

To get a template using the CLI, run:

```bash
crypto-condor-cli get-wrapper AES -l Python
```

To get a practical example, run:

```bash
crypto-condor-cli get-wrapper AES -l Python --example 1
````

## Encrypt

To test an implementation of AES encryption, the function must:

- implement the {protocol}`crypto_condor.primitives.AES.Encrypt` protocol;
- follow the naming convention.

```
CC_AES_<mode>_encrypt
```

Where `mode` is a supported mode of operation (see
{enum}`crypto_condor.primitives.AES.Mode`). This tests all key lengths. A specific one
can be indicated:

```
CC_AES_<mode>_<length>_encrypt
```

Where `length` is one of `128`, `192`, or `256`.


## Decrypt

To test an implementation of AES decryption, the function must:

- implement the {protocol}`crypto_condor.primitives.AES.Decrypt` protocol;
- follow the naming convention.

```
CC_AES_<mode>_decrypt
```

Where `mode` is a supported mode of operation (see
{enum}`crypto_condor.primitives.AES.Mode`). This tests all key lengths. A specific one
can be indicated:

```
CC_AES_<mode>_<key length>_decrypt
```

Where `length` is one of `128`, `192`, or `256`.
