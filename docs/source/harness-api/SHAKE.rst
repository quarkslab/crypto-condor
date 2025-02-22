SHAKE
=====

Test digest
-----------

|cc| tests SHAKE implementations through a single ``digest`` function that is equivalent to the following pseudo-code:

.. code:: python

    def digest(data: bytes, output_length: int) -> bytes:
        h = shake128.init()
        h.update(data)
        return h.final(output_length)

Naming convention
^^^^^^^^^^^^^^^^^

To test a SHAKE implementation, the function must conform to one of these conventions:

.. code::

    CC_SHAKE_128_digest[_bit]

    CC_SHAKE_256_digest[_bit]

``bit`` is an **optional** parameter. If present, the implementation is considered to be bit-oriented. By default, it is considered byte-oriented.

Function signature
^^^^^^^^^^^^^^^^^^

Its signature must be:

.. c:function:: int digest(uint8_t *digest, const size_t digest_size, const uint8_t *input, const size_t input_size)

    Produces digests of arbitrary length.

    :param digest: **[Out]** An allocated buffer, used to return the digest.
    :param digest_size: **[In]** The desired size of the digest.
    :param input: **[In]** The input data.
    :param input_size: **[In]** The size of the input data in bytes.
    :returns: A status value.
    :retval 0: OK
    :retval -1: Digest failed.

Example
^^^^^^^

To test that the harness integration is working correctly, we use the following OpenSSL harness.

.. literalinclude:: ../../../tests/harness/SHAKE.harness.c
   :language: c

Compile the shared library with the ``-lssl -lcrypto`` options.

.. code:: bash

   gcc -fPIC -shared shake_harness.c -o shake.so -lssl -lcrypto

Then test the harness.

.. code:: bash

   crypto-condor-cli test harness shake.so
