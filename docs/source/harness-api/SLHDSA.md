# SLH-DSA harness

A quick overview to explain the difference between the different variants and
versions of SLH-DSA.

- SLH-DSA has two variants: pure SLH-DSA and HashSLH-DSA. The first one signs
  the messages as-is, while the second one hashes the messages before signing.
  Hashing requires an *approved* hash function or XOF, such as SHA-512 or
  SHAKE256. The external API of SLH-DSA takes the message as input for both
  variants, the hashing is done inside the function. However, the pre-hash
  variant takes an additional string argument, `ph`, that indicates the hash
  function or XOF to use.
- SLH-DSA also features two versions: a *hedged*, randomized one, and a
  *deterministic* one. The hedged version is the default.

Since the pre-hash variant introduces an additional argument, the functions are
separated by variant.

Signing functions have an optional modifier `_det` to test the deterministic
version. Verifying functions do *not* have this parameter, as the verification
algorithm is the same for deterministic or hedged signatures.

## Test signing

```{warning}
To test signing with the hedged version on its own requires a reference
implementation to verify the signature produced. We are currently in the process
of adding support for an implementation, so currently only the *deterministic*
version can be tested on its own. You can, however, test the hedged version with
its corresponding verification function by testing the
[invariant](#test-invariant).
```
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

The function must have the following arguments:

```{eval-rst}
.. c:function:: int SLHDSA_sign(\
    uint8_t *sig, size_t sig_size,\
    const uint8_t *msg, size_t msg_size,\
    const uint8_t *ctx, size_t ctx_size,\
    const uint8_t *sk, size_t sk_size,\
    const char *ph, size_t ph_size)

    Signs with SLH-DSA.

    :param sig: **[Out]** An allocated buffer to return the signature.
    :param sig_size: **[In]** The size of ``sig`` in bytes.
    :param msg: **[In]** The message to sign.
    :param msg_size: **[In]** The size of ``msg`` in bytes.
    :param ctx: **[In]** The context string, can be empty.
    :param ctx_size: **[In]** The size of ``ctx`` in bytes.
    :param sk: **[In]** The secret key.
    :param sk_size: **[In]** The size of ``sk`` in bytes.
    :param ph: **[In]** The string indicating which hash function or XOF to use for the **pre-hash** variant. For the **pure** variant, it is an empty array.
    :param ph_size: **[In]** The size of ``ph`` in bytes, 0 for the pure variant.
    :returns: A status value.
    :retval 1: Operation successful.
    :retval 0: An error occurred.
```

## Test verifying

To test a function that verifies pure SLH-DSA signatures, create a function with
the following name:

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

The function must have the following arguments:

```{eval-rst}
.. c:function:: int SLHDSA_verify(\
    const uint8_t *sig, size_t sig_size,\
    const uint8_t *msg, size_t msg_size,\
    const uint8_t *ctx, size_t ctx_size,\
    const uint8_t *sk, size_t sk_size,\
    const char *ph, size_t ph_size)

    Verifies an SLH-DSA signature.

    :param sig: **[In]** An allocated buffer to return the signature.
    :param sig_size: **[In]** The size of ``sig`` in bytes.
    :param msg: **[In]** The message to sign.
    :param msg_size: **[In]** The size of ``msg`` in bytes.
    :param ctx: **[In]** The context string, can be empty.
    :param ctx_size: **[In]** The size of ``ctx`` in bytes.
    :param sk: **[In]** The secret key.
    :param sk_size: **[In]** The size of ``sk`` in bytes.
    :param ph: **[In]** The string indicating which hash function or XOF to use for the **pre-hash** variant. For the **pure** variant, it is an empty array.
    :param ph_size: **[In]** The size of ``ph`` in bytes, 0 for the pure variant.
    :returns: A status value.
    :retval 1: The signature is valid.
    :retval 0: The signature is invalid.
    :retval -1: An error occurred.
```

## Test invariant

Signing a message then verifying the signature with the same implementation
should always work, unless an error occurs while signing. To test this
invariant, first create a [signing function](#test-signing) and a [verifying
function](#test-verifying) for the same parameter set. This works for both
hedged and deterministic signing, although if both functions are defined, {{ cc
}} defaults to testing the hedged version.

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
existence, and uses the function name to determine the name of the signing and
verifying functions.

### Example

To test the invariant for SLH-DSA-SHA2-128s:

```c
int CC_SLHDSA_sha2_128s_sign_pure(...) { ... }

int CC_SLHDSA_sha2_128s_verify_pure(...) { ... }

int CC_SLHDSA_sha2_128s_invariant_pure() { return 1; }
```
