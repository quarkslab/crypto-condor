# HQC harness

## Test encapsulation

```{attention}
Testing encapsulation requires a reference implementation to decapsulate the
ciphertexts, as encapsulation is a non-deterministic operation. We are working
on integrating one so this function is only for testing the
encapsulation/decapsulation invariant for now.
```

The naming convention for the encapsulation function is:

```
CC_HQC_encaps_<paramset>
```

Where `paramset` is one of: `hqc128`, `hqc192`, `hqc256`.

The harness function must have the following signature:

```{eval-rst}
.. c:function:: int HQC_encaps(\
    uint8_t *ct, size_t ct_size,\
    uint8_t *ss, size_t ss_size,\
    const uint8_t *pk, size_t pk_size)

    Encapsulates with HQC.

    :param ct: **[Out]** An allocated buffer to return the resulting ciphertext.
    :param ct_size: **[In]** The size in bytes of ``ct``.
    :param ss: **[Out]** An allocated buffer to return the resulting shared secret.
    :param ss_size: **[In]** The size in bytes of ``ss``.
    :param pk: **[In]** The public key to encapsulate to.
    :param pk_size: **[In]** The size in bytes of ``pk``.
    :returns: A status value.
    :retval 1: OK.
    :retval 0: An error occurred.
```

## Test decapsulation

The naming convention for the decapsulation function is:

```
CC_HQC_decaps_<paramset>
```

Where `paramset` is one of: `hqc128`, `hqc192`, `hqc256`.

The harness function must have the following signature:

```{eval-rst}
.. c:function:: int HQC_decaps(\
    uint8_t *ss, size_t ss_size,\
    const uint8_t *sk, size_t sk_size,\
    const uint8_t *ct, size_t ct_size)

    Decapsulates a shared secret with HQC.

    :param ss: **[Out]** An allocated buffer to return the resulting shared secret.
    :param ss_size: **[In]** The size in bytes of ``ss``.
    :param sk: **[In]** The secret key to use for decapsulation.
    :param sk_size: **[In]** The size in bytes of ``sk``.
    :param ct: **[In]** The ciphertext.
    :param ct_size: **[In]** The size in bytes of ``ct``.
    :returns: A status value.
    :retval 1: OK.
    :retval 0: An error occurred.
```

## Test encapsulation/decapsulation invariant

Encapsulating to a public key then decapsulating with the corresponding secret
key should always yield the same share secret. To test this invariant, create
the following function **and** a harness for both encapsulation and
decapsulation, as detailed above.

```
CC_HQC_invariant_<paramset>
```

Where `paramset` is one of: `hqc128`, `hqc192`, `hqc256`.

The function is a stub to indicate {{ cc }} to test the invariant, no operations
are actually performed with it.

```{eval-rst}
.. c:function:: void HQC_invariant(void)
```

For example:

```c
int CC_HQC_encaps_hqc128(...) {
    ...
}

int CC_HQC_decaps_hqc128(...) {
    ...
}

void CC_HQC_invariant_hqc128() {};
```
