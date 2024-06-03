SHA
---

Digest
^^^^^^

To test a function that generates SHA digests, the function must be called:

.. code::
   
   CC_<algorithm>_digest_[bit]
   
* ``algorithm`` is a **required** parameter. Valid values are:
   * ``SHA_1``
   * ``SHA_224``, ``SHA_256``, ``SHA_384``, ``SHA_512``.
      * ``SHA_512_224`` and ``SHA_512_256``.
   * ``SHA_3_224``, ``SHA_3_256``, ``SHA_3_384``, ``SHA_3_512``.
* ``_bit`` is an **optional** suffix. If present, the implementation is considered to be bit-oriented. By default it is considered byte-oriented.

The function must have the following signature:

.. c:function:: void SHA_digest(uint8_t *digest, const uint8_t *input, size_t input_size)

   :param digest: **[Out]** A buffer to store the resulting hash. Its size is inferred from the SHA function used.
   :param input: **[In]** The input data.
   :param input_size: **[In]** The size of the input data in bytes.

Examples:

* SHA-1:

.. code:: c

   void CC_SHA_1_digest(uint8_t *digest, const uint8_t *input, size_t input_size);

* SHA-256:

.. code:: c

   void CC_SHA_256_digest(uint8_t *digest, const uint8_t *input, size_t input_size);

* SHA-512/224:

.. code:: c

   void CC_SHA_512_224_digest(uint8_t *digest, const uint8_t *input, size_t input_size);

* SHA3-512:

.. code:: c

   void CC_SHA_3_512_digest(uint8_t *digest, const uint8_t *input, size_t input_size);

* Bit-oriented SHA3-512:

.. code:: c

   void CC_SHA_3_512_digest_bit(uint8_t *digest, const uint8_t *input, size_t input_size);