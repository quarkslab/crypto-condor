SHA
===

Digest
------

``digest`` is a single operation, equivalent to the following pseudo-code:

.. code:: python

   h = sha.init()
   h.update(data)
   h.digest()

Naming convention
^^^^^^^^^^^^^^^^^

.. code::

   CC_<algorithm>_digest

Where ``algorithm`` is one of:

* ``SHA_1``
* ``SHA_224``, ``SHA_256``, ``SHA_384``, ``SHA_512``.
    * ``SHA_512_224`` and ``SHA_512_256``.
* ``SHA_3_224``, ``SHA_3_256``, ``SHA_3_384``, ``SHA_3_512``.

Function signature
^^^^^^^^^^^^^^^^^^

The function must have the following signature:

.. c:function:: int SHA_digest(uint8_t *digest, const size_t digest_size, const uint8_t *input, const size_t input_size)

   :param digest: **[Out]** An allocated buffer to return the resulting digest.
   :param digest_size: **[In]** The size of the ``digest`` buffer.
   :param input: **[In]** The input data.
   :param input_size: **[In]** The size of the input data in bytes.
   :returns: A status value, following OpenSSL's convention.
   :retval 1: OK.
   :retval 0: Digest failed.

Example
^^^^^^^

To test that the harness integration is working correctly, we use the following OpenSSL harness:

.. literalinclude:: ../../../tests/harness/SHA.harness.c
   :language: c

Compile the shared library with the ``-lssl -lcrypto`` options.

.. code:: bash

   gcc -fPIC -shared sha_harness.c -o sha.so -lssl -lcrypto

Then test the harness.

.. code:: bash

   crypto-condor-cli test harness sha.so
