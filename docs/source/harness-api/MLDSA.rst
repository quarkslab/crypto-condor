ML-DSA
------

In ML-DSA, the size of the public key, secret key, and signature is fixed.  These
parameters are still provided to the implementation, but if the implementation you are
testing doesn't require them, that may be the reason why.

.. csv-table:: Parameter sets and object sizes (in bytes)
    :header-rows: 1
    :stub-columns: 1

    "Parameter set", "Public key", "Private key", "Signature"
    ``44``, 1312, 2560, 2420
    ``65``, 1952, 4032, 3309
    ``77``, 2592, 4896, 4627

Sign
^^^^

To test a function that signs with ML-DSA, its name must conform to the following convention:

.. code::

    CC_MLDSA_<param set>_sign

Its signature must be:

.. c:function:: void MLDSA_sign(\
    uint8_t *sig, size_t siglen,\
    const uint8_t *msg, size_t msglen,\
    const uint8_t *ctx, size_t ctxlen,\
    const uint8_t *sk, size_t sklen)

    Signs a message with MLDSA.

    :param sig: **[Out]** A buffer to store the resulting signature.
    :param siglen: **[In]** The size of the signature buffer in bytes.
    :param msg: **[In]** The message to sign.
    :param msglen: **[In]** The size of the message in bytes.
    :param ctx: **[In]** The context string, can be empty.
    :param ctxlen: **[In]** The size of the context string in bytes.
    :param sk: **[In]** The secret key to use.
    :param sklen: **[In]** The size of the secret key in bytes.

Example:

* ML-DSA-44:

.. code:: c

    void CC_MLDSA_44_sign(uint8_t *sig, size_t siglen,
                          const uint8_t *msg, size_t msglen,
                          const uint8_t *ctx, size_t ctxlen,
                          const uint8_t *sk, size_t sklen);

Verify
^^^^^^

To test a function that verifies ML-DSA signatures, its name must conform to the following convention:

.. code::

    CC_MLDSA_<param set>_verify

Its signature must be:

.. c:function:: int MLDSA_verify(\
    const uint8_t *sig, size_t siglen,\
    const uint8_t *msg, size_t msglen,\
    const uint8_t *ctx, size_t ctxlen,\
    const uint8_t *pk, size_t pklen)

    :param sig: **[In]** The signature to verify.
    :param siglen: **[In]** The size of the signature in bytes.
    :param msg: **[In]** The message that was signed.
    :param msglen: **[In]** The size of the message in bytes.
    :param ctx: **[In]** The context string, can be empty.
    :param ctxlen: **[In]** The size of the context string in bytes.
    :param pk: **[In]** The public key.
    :param pklen: **[In]** The size of the public key in bytes.
    :returns: The result of the verification.
    :retval 0: OK.
    :retval -1: The signature is invalid.

Example:

* ML-DSA-44:

.. code:: c

    int CC_MLDSA_44_verify(const uint8_t *sig, size_t siglen,
                           const uint8_t *msg, size_t msglen,
                           const uint8_t *ctx, size_t ctxlen,
                           const uint8_t *pk, size_t pklen);
