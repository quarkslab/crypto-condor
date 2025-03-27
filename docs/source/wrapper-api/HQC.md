# HQC wrapper

```{eval-rst}
.. currentmodule:: crypto_condor.primitives.HQC
```

## Test encapsulation

```{attention}
Testing encapsulation requires a reference implementation to decapsulate the
ciphertexts, as encapsulation is a non-deterministic operation. We are working
on integrating one so this function is only for testing the
encapsulation/decapsulation invariant for now.
```

### Naming convention

The naming convention for the encapsulation function is:

```
CC_HQC_<paramset>_encaps
```

Where `paramset` is one of: `128`, `192`, `256`.

### Protocol

The wrapper function must implement the `Encaps` protocol:

```{eval-rst}
.. autoprotocol:: Encaps
    :noindex:
```

## Test decapsulation

If a decapsulation function is found, it is tested as an independent operation.
It can also be tested as part of the encapsulation-decapsulation invariant
described below.

### Naming convention

The naming convention for the decapsulation function is:

```
CC_HQC_<paramset>_decaps
```

Where `paramset` is one of: `128`, `192`, `256`.

### Protocol

The wrapper function must implement the `Decaps` protocol:

```{eval-rst}
.. autoprotocol:: Decaps
    :noindex:
```

## Test encapsulation/decapsulation invariant

Encapsulating and decapsulating with the same implementation and key pair should
always yield the same shared secret. To test this invariant, {{ cc }} expects
both operations for a given parameter set (as detailed above) as well as a
**stub function** to indicate to test the invariant. No actual operations are
performed with the following function.

### Naming convention
```
CC_HQC_<paramset>_invariant
```

Where `paramset` is one of: `128`, `192`, `256`.

### Example

We define the `encaps` and `decaps` functions for HQC-128, as well as the
`CC_HQC_128_invariant` stub to test them together.

```python
def CC_HQC_128_encaps(pk: bytes) -> tuple[bytes, bytes]:
    ...

def CC_HQC_128_decaps(sk: bytes, ct: bytes) -> bytes:
    ...

def CC_HQC_128_invariant() -> None:
    pass
```
