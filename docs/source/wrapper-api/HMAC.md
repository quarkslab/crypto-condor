# HMAC wrappers

```{currentmodule} crypto_condor.primitives.HMAC

```

## Digest

Generates a MAC tag using HMAC.

### Naming convention

```
CC_HMAC_digest_<hash function>
```

Where `hash function` is one of:

- `sha1`, `sha224`, `sha256`, `sha384`, `sha512`.
- `sha3_224`, `sha3_256`, `sha3_384`, `sha3_512`.

### Protocol

The function must conform to the following protocol:

```{eval-rst}
.. autoprotocol:: Digest
    :noindex:
```

## Verify

Verifies an HMAC tag.

### Naming convention

```
CC_HMAC_verify_<hash function>
```

Where `hash function` is one of:

- `sha1`, `sha224`, `sha256`, `sha384`, `sha512`.
- `sha3_224`, `sha3_256`, `sha3_384`, `sha3_512`.

### Protocol

The function must conform to the following protocol:

```{eval-rst}
.. autoprotocol:: Verify
    :noindex:
```

## Example

```{literalinclude} ../../../crypto_condor/resources/wrappers/HMAC/Python-examples/1/hmac_wrapper_example.py
```
