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
CC_<algorithm>_digest
```

Where `algorithm` is one of:

- `SHA_1`
- `SHA_224`, `SHA_256`, `SHA_384`, `SHA_512`
- `SHA_512_224`, `SHA_512_256`
- `SHA_3_224`, `SHA_3_256`, `SHA_3_384`, `SHA_3_512`

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
