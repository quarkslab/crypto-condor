# HMAC harness

## Digest

{{ cc }} tests HMAC implementations through a single `digest` function that is
equivalent to the following pseudo-code:

```python
def digest(key: bytes, msg: bytes) -> bytes:
    h = hmac.init(key)
    h.update(msg)
    return h.final()
```

### Naming convention

```
CC_HMAC_digest_<hash function>
```

Where `hash function` is one of:

- `sha1`.
- SHA-2 family: `sha224`, `sha256`, `sha384`, `sha512`.
- SHA-3 family: `sha3224`, `sha3256`, `sha3384`, `sha3512`.

### Python harness

```{eval-rst}
.. autoprotocol:: crypto_condor.vectors.hmac.Digest
    :noindex:
```

#### Example

```{literalinclude} ../../../tests/harness/HMAC/digest.py
```

### C harness

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
    :retval 0: Success.
    :retval -1: Error.
```

#### Example

To test the harness for this function, we use the following OpenSSL harness:

```{literalinclude} ../../../tests/harness/HMAC/digest.c
:language: c
```

Compile the shared library with the `-lssl -lcrypto` options:

```bash
gcc -fPIC -shared hmac_digest.c -o hmac_digest.so -lssl -lcrypto
```

Then test the harness.

```bash
crypto-condor-cli test harness hmac_digest.so
```

## Verify MAC

FIXME: when do we use truncated tags? depending on that answer, we can accept or
not implementations that do not verify truncated tags.
```{attention}
The tags used by {{ cc }} may be **truncated**, meaning that comparing the MAC
computed by the implementation with the one provided by {{ cc }} through the
harness may fail.

The tags used by {{ cc }} may be **truncated**, meaning that comparing the entire MAC to
the tag passed by {{ cc }} may fail. The size of the regular MAC tag is equal to the
output size of the underlying hash function. This is given through the `md_size`
parameter.
```

### Naming convention

```
CC_HMAC_verify_<hash function>
```

Where `hash function` is one of:

- `sha1`.
- SHA-2 family: `sha224`, `sha256`, `sha384`, `sha512`.
- SHA-3 family: `sha3224`, `sha3256`, `sha3384`, `sha3512`.

### Python harness

```{eval-rst}
.. autoprotocol:: crypto_condor.vectors.hmac.Verify
    :noindex:
```

#### Example

```{literalinclude} ../../../tests/harness/HMAC/verify.py
```

### C harness

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
gcc -fPIC -shared hmac_verify.c -o hmac_verify.so -lssl -lcrypto
```

Then test the harness.

```bash
crypto-condor-cli test harness hmac_verify.so
```
