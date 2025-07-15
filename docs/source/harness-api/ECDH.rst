ECDH harness
============

Key exchange with public point
------------------------------

Naming convention
^^^^^^^^^^^^^^^^^

.. code::

   CC_ECDH_exchange_point_<curve>

Where ``curve`` is one of:

* ``P192``, ``P224``, ``P256``, ``P384``, ``P521``.
* ``B163``, ``B223``, ``B283``, ``B409``, ``B571``.
* ``K163``, ``K223``, ``K283``, ``K409``, ``K571``.

.. attention::

   OpenSSL 3.0 does not support ``B`` or ``K`` curves, so they are untested in harness mode.

Function signature
^^^^^^^^^^^^^^^^^^

.. c:function:: int ECDH_exchange_point(uint8_t ss[512], size_t *ss_size, const uint8_t *secret, const size_t secret_size, const uint8_t *point, const size_t point_size)

   Performs an ECDH key exchange with an encoded uncompressed point.

   :param ss: **[Out]** An allocated buffer to return the shared secret.
   :param ss_size: **[Out]** A pointer to return the actual size of the shared secret.
   :param secret: **[In]** Peer A's secret value as a big-endian array of bytes.
   :param secret_size: **[In]** The size of ``secret`` in bytes.
   :param point: **[In]** Peer B's public key as an encoded uncompressed point.
   :param point_size: **[In]** The size of ``point_size`` in bytes.
   :returns: A status code.
   :retval 1: OK.
   :retval 0: An error occurred.

Example
^^^^^^^

To test that the harness integration is working correctly, we use the following OpenSSL harness:

.. literalinclude:: ../../../tests/harness/ECDH_point.harness.c
   :language: c

Compile the shared library with the ``-lssl -lcrypto`` options.

.. code:: bash

   gcc -fPIC -shared ecdh_point_harness.c -o ecdh_point.so -lssl -lcrypto

Then test the harness.

.. code:: bash

   crypto-condor-cli test harness ecdh_point.so

Key exchange with X.509 key
---------------------------

Naming convention
^^^^^^^^^^^^^^^^^

.. code::

   CC_ECDH_exchange_point_<curve>

Where ``curve`` is one of:

* ``P224``, ``P256``, ``P384``, ``P521``.
* ``brainpoolP224r1``, ``brainpoolP256r1``, ``brainpoolP320r1``, ``brainpoolP384r1``, ``brainpoolP512r1``.
* ``secp256k1``.
* ``B283``, ``B409``, ``B571``.
* ``K283``, ``K409``, ``K571``.

.. attention::

   OpenSSL 3.0 does not support ``B`` or ``K`` curves, so they are untested in harness mode.

Function signature
^^^^^^^^^^^^^^^^^^

.. c:function:: int ECDH_exchange_x509(uint8_t ss[512], size_t *ss_size, const uint8_t *secret, const size_t secret_size, const uint8_t *pub, const size_t pub_size)

   Performs an ECDH key exchange with an encoded uncompressed point.

   :param ss: **[Out]** An allocated buffer to return the shared secret.
   :param ss_size: **[Out]** A pointer to return the actual size of the shared secret.
   :param secret: **[In]** Peer A's secret value as a big-endian array of bytes.
   :param secret_size: **[In]** The size of ``secret`` in bytes.
   :param pub: **[In]** Peer B's public key as an X.509 key.
   :param point_size: **[In]** The size of ``pub_size`` in bytes.
   :returns: A status code.
   :retval 1: OK.
   :retval 0: An error occurred.

Example
^^^^^^^

To test that the harness integration is working correctly, we use the following OpenSSL harness:

.. literalinclude:: ../../../tests/harness/ECDH_x509.harness.c
   :language: c

Compile the shared library with the ``-lssl -lcrypto`` options.

.. code:: bash

   gcc -fPIC -shared ecdh_x509_harness.c -o ecdh_x509.so -lssl -lcrypto

Then test the harness.

.. code:: bash

   crypto-condor-cli test harness ecdh_x509.so
