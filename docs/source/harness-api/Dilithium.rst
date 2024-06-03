Dilithium
---------

.. include:: ../_static/dilithium-vectors-warning.rst.txt

In Dilithium, the size of the public key, secret keys, and signature is fixed.  These
parameters are still provided to the hooked function, but if the implementation you are
testing doesn't require them, that may be the reason why.

.. csv-table:: Parameter sets and object sizes (in bytes)
    :header-rows: 1
    :stub-columns: 1

    "Parameter set", "Public key", "Private key", "Signature"
    ``2``, 1312, 2528, 2420
    ``3``, 1952, 4000, 3293
    ``5``, 2592, 4864, 4595

Sign
^^^^

To test a function that signs with Dilithium, its name must conform to the following convention:

.. code::

    CC_Dilithium_<param set>_sign

Its signature must be:

.. c:function:: void Dilithium_sign(\
    uint8_t *sig, size_t siglen,\
    const uint8_t *msg, size_t msglen,\
    const uint8_t *sk, size_t sklen)

    Signs a message with Dilithium.

    :param sig: **[Out]** A buffer to store the resulting signature.
    :param siglen: **[In]** The size of the signature buffer in bytes.
    :param msg: **[In]** The message to sign.
    :param msglen: **[In]** The size of the message in bytes.
    :param sk: **[In]** The secret key to use.
    :param sklen: **[In]** The size of the secret key in bytes.

Example:

* Dilithium2:

.. code:: c

    void CC_Dilithium_2_sign(uint8_t *sig, size_t siglen,
                             const uint8_t *msg, size_t msglen,
                             const uint8_t *sk, size_t sklen);

Verify
^^^^^^

To test a function that verifies Dilithium signatures, its name must conform to the following convention:

.. code::

    CC_Dilithium_<param set>_verify

Its signature must be:

.. c:function:: int Dilithium_verify(\
    const uint8_t *sig, size_t siglen,\
    const uint8_t *msg, size_t msglen,\
    const uint8_t *pk, size_t pklen)

    :param sig: **[In]** The signature to verify.
    :param siglen: **[In]** The size of the signature in bytes.
    :param msg: **[In]** The message that was signed.
    :param msglen: **[In]** The size of the message in bytes.
    :param pk: **[In]** The public key.
    :param pklen: **[In]** The size of the public key in bytes.
    :returns: The result of the verification.
    :retval 0: OK.
    :retval -1: The signature is invalid.

Example:

* Dilithium2:

.. code:: c

    int CC_Dilithium_2_verify(const uint8_t *sig, size_t siglen,
                              const uint8_t *msg, size_t msglen,
                              const uint8_t *pk, size_t pklen);
