# HMAC harness

## Test digest

{{ cc }} tests HMAC implementations through a single `digest` function that is
equivalent to the following pseudo-code:

```python
def digest(key: bytes, msg: bytes) -> bytes:
    h = hmac.init(key)
    h.update(msg)
    return h.final()
```

### Naming convention

The function must conform to the following convention:

```
CC_HMAC_digest_<hash function>
```

Where `hash function` is one of:

- `sha1`, `sha224`, `sha256`, `sha384`, `sha512`.
- `sha3_224`, `sha3_256`, `sha3_384`, `sha3_512`.

### Function signature

Its signature must be:

```{eval-rst}
.. c:function:: int HMAC_digest(uint8_t *mac, const size_t mac_size, const uint8_t *key, const size_t key_size, const uint8_t *msg, const size_t msg_size)

    Generates HMAC tags.

    :param mac: **[Out]** An allocated buffer to return the MAC tag.
    :param mac_size: **[In]** The size of the allocated buffer in bytes.
    :param key: **[In]** The secret key.
    :param key_size: **[In]** The size of the secret key in bytes.
    :param msg: **[In]** The message to authenticate.
    :param msg_size: **[In]** The size of the message in bytes.
    :returns: A status value.
    :retval 1: OK
    :retval 0: An error occurred.
```

### Example

To test the harness for this function, we use the following OpenSSL harness:

```{literalinclude} ../../../tests/harness/HMAC_digest.harness.c
:language: c
```

Compile the shared library with the `-lssl -lcrypto` options:

```bash
gcc -fPIC -shared hmac_digest_harness.c -o hmac_digest.so -lssl -lcrypto
```

Then test the harness.

```bash
crypto-condor-cli test harness hmac_digest.so
```

## Test verify

HMAC tag verification requires computing the tag again to compare it with the given
value.

### Naming convention

The function must conform to the following convention:

```
CC_HMAC_verify_<hash function
```

Where `hash function` is one of:

- `sha1`, `sha224`, `sha256`, `sha384`, `sha512`.
- `sha3_224`, `sha3_256`, `sha3_384`, `sha3_512`.

### Function signature


```{attention}
The tags used by {{ cc }} may be **truncated**, meaning that comparing the entire MAC to
the tag passed by {{ cc }} may fail. The size of the regular MAC tag is equal to the
output size of the underlying hash function. This is given through the `md_size`
parameter.
```

Its signature must be:

```{eval-rst}
.. c:function:: int HMAC_verify(const uint8_t *mac, const size_t mac_size, const size_t md_size, const uint8_t *key, const size_t key_size, const uint8_t *msg, const size_t msg_size)

    Verifies HMAC tags.

    :param mac: **[In]** The MAC tag.
    :param mac_size: **[In]** The size of the MAC tag in bytes. Note that the tag **may be truncated**, so the size may differ from ``md_size``.
    :param md_size: **[In]** The output size of the hash function in bytes. This is the size of a full MAC tag and may differ from ``mac_size``.
    :param key: **[In]** The secret key.
    :param key_size: **[In]** The size of the secret key in bytes.
    :param msg: **[In]** The message to authenticate.
    :param msg_size: **[In]** The size of the message in bytes.
    :returns: A status value.
    :retval 1: Tag is valid.
    :retval 0: Tag is invalid.
    :retval -1: An error occurred.
```

### Example

To test the harness for this function, we use the following OpenSSL harness:

```{literalinclude} ../../../tests/harness/HMAC_verify.harness.c
:language: c
```

Compile the shared library with the `-lssl -lcrypto` options:

```bash
gcc -fPIC -shared hmac_verify_harness.c -o hmac_verify.so -lssl -lcrypto
```

Then test the harness.

```bash
crypto-condor-cli test harness hmac_verify.so
```
