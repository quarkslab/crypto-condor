# SHAKE wrappers

## Digest

`digest` is a single operation equivalent to:

```python
h = SHAKE.init()
h.update(some_data)
h.digest(length) # or h.finalize() or h.squeeze()
```

### Naming convention

To test a function that implements `digest`, create a function with one of the
following names:

```
CC_SHAKE_128_digest
CC_SHAKE_256_digest
```

### Protocol

The function must implement the following protocol:

```{eval-rst}
.. autoprotocol:: crypto_condor.primitives.SHAKE.Xof
    :noindex:
```

### Example

We use PyCryptodome for the wrapper example:

```{literalinclude} ../../../crypto_condor/resources/wrappers/SHAKE/Python-examples/1/shake_wrapper_example.py
```
