# SHA wrappers

## Digest

``digest`` is a single operation equivalent to the following pseudo-code:

```python
def digest(data: bytes) -> bytes:
    h = sha.init()
    h.update(data)
    return h.digest()
```
### Naming convention

To test an implementation of `digest`, create a function with the following
name:

```
CC_SHA_digest_<algorithm>
```

Where `algorithm` is one of:

- `sha1`.
- SHA-2 family: `sha224`, `sha256`, `sha384`, `sha512`, `sha512224` (SHA-512/224), `sha512256` (SHA-512/256).
- SHA-3 family: `sha3224`, `sha3256`, `sha3384`, `sha3512`.

### Protocol

The function must implement the following protocol:

```{eval-rst}
.. autoprotocol:: crypto_condor.primitives.SHA.HashFunction
    :noindex:
```

### Example

We use PyCryptodome for the wrapper example:

```{literalinclude} ../../../crypto_condor/resources/wrappers/SHA/Python-examples/1/sha_wrapper_example.py
```
