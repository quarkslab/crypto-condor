# SLH-DSA wrapper API

```{eval-rst}
.. currentmodule:: crypto_condor.primitives.SLHDSA
```

## Test signing

To test a function that signs with SLH-DSA, create a function with the following
name:

```
CC_SLHDSA_<parameter set>_sign_<variant>[_det]
```

Where:

- `parameter set` is one of:
    - `sha2_128s`, `sha2_192s`, `sha2_256s`
    - `sha2_128f`, `sha2_192f`, `sha2_256f`
    - `shake_128s`, `shake_192s`, `shake_256s`
    - `shake_128f`, `shake_192f`, `shake_256f`
- `variant` is one of `pure` and `prehash`
- `_det` is an optional parameter indicating that the function implements the
  deterministic version instead of the hedged version.

The function must conform to the following protocol:

```{eval-rst}
.. autoprotocol:: Sign
    :noindex:
```

## Test verifying

To test a function that verifies SLH-DSA signatures, create a function with the
following name:

```
CC_SLHDSA_<parameter set>_verify_<variant>
```

Where:

- `parameter set` is one of:
    - `sha2_128s`, `sha2_192s`, `sha2_256s`
    - `sha2_128f`, `sha2_192f`, `sha2_256f`
    - `shake_128s`, `shake_192s`, `shake_256s`
    - `shake_128f`, `shake_192f`, `shake_256f`
- `variant` is one of `pure` and `prehash`

The function must conform to the following protocol:

```{eval-rst}
.. autoprotocol:: Verify
    :noindex:
```

## Test sign-verify invariant

Signing a message then verifying the signature with the same implementation
should always work, unless an error occurs while signing. To test this
invariant, first create a [signing function](#test-signing) and a [verifying
function](#test-verifying) for the same parameter set.

Then, create a function with the following name:

```
CC_SLHDSA_<parameter set>_invariant_<variant>
```

Where:

- `parameter set` is one of:
    - `sha2_128s`, `sha2_192s`, `sha2_256s`
    - `sha2_128f`, `sha2_192f`, `sha2_256f`
    - `shake_128s`, `shake_192s`, `shake_256s`
    - `shake_128f`, `shake_192f`, `shake_256f`
- `variant` is one of `pure` and `prehash`

The function is a stub: it is not executed, {{ cc }} only checks for its
existence.

### Example

To test the invariant for SLH-DSA-SHA2-128s:

```python

def CC_SLHDSA_sha2_128s_sign_pure(sk: bytes, msg: bytes, ctx: bytes, ph: str) -> bytes:
    ...

def CC_SLHDSA_sha2_128s_verify_pure(pk: bytes, msg: bytes, sig: bytes, ctx: bytes, ph: str) -> bool:
    ...

def CC_SLHDSA_sha2_128s_invariant_pure():
    return
```
