SHAKE
-----

Digest
^^^^^^

To test a SHAKE implementation, the function must conform to one of these conventions:

.. code::

    CC_SHAKE_128_digest[_bit]

    CC_SHAKE_256_digest[_bit]

* ``bit`` is an **optional** parameter. If present, the implementation is considered to be bit-oriented. By default, it is considered byte-oriented.

Its signature must be:

.. c:function:: void SHAKE_digest(uint8_t *digest, size_t digest_size, const uint8_t *input, size_t input_size)

    Produces digests of arbitrary length.

    :param digest: **[Out]** A buffer to store the resulting digest.
    :param digest_size: **[In]** The desired size of the digest.
    :param input: **[In]** The input data.
    :param input_size: **[In]** The size of the input data in bytes.

Examples:

* SHAKE128:

.. code:: c

    void CC_SHAKE_128_digest(uint8_t *digest, size_t digest_size,
                            const uint8_t *input, size_t input_size);

* SHAKE256:

.. code:: c

    void CC_SHAKE_256_digest(uint8_t *digest, size_t digest_size,
                            const uint8_t *input, size_t input_size);

* Bit-oriented SHAKE256:

.. code:: c

    void CC_SHAKE_256_digest_bit(uint8_t *digest, size_t digest_size,
                                const uint8_t *input, size_t input_size);
