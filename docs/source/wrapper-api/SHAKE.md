# SHAKE wrappers

## Digest

`digest` is a single operation equivalent to:

```python
h = SHAKE.init()
h.update(some_data)
h.digest(length) # or h.finalize() or h.squeeze()
```

The naming convention for byte-oriented implementations is:

```
CC_SHAKE_<algorithm>_digest
```

And for bit-oriented ones:

```
CC_SHAKE_<algorithm>_digest_bit
```

Where:

- `algorithm` is one of: `128`, `256`.
