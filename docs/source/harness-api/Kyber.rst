Kyber
-----

.. include:: ../_static/kyber-version-warning.rst.txt

In Kyber, the size of the public and private keys, the ciphertext, and shared secret
[#]_ is fixed.  These parameters are still provided to the CC function, but if the
implementation you are testing doesn't require them, that may be the reason why.

.. csv-table:: Parameter sets and object sizes (in bytes)
    :header-rows: 1
    :stub-columns: 1

    "Parameter set", "Private key", "Public Key", "Ciphertext", "Shared secret"
    ``512``, 1632, 800, 768, 32
    ``512_90s``, 1632, 800, 768, 32
    ``768``, 2400, 1184, 1088, 32
    ``768_90s``, 2400, 1184, 1088, 32
    ``1024``, 3168, 1568, 1568, 32
    ``1024_90s``, 3168, 1568, 1568, 32

Encapsulate
^^^^^^^^^^^

To test a function that encapsulates with Kyber, its name must conform to the following convention:

.. code::

    CC_Kyber_<param set>_encapsulate

Its signature must be:

.. c:function:: void Kyber_encapsulate(\
    uint8_t *ct, size_t ct_sz,\
    uint8_t *ss, size_t ss_sz,\
    const uint8_t *pk, size_t pk_sz)

    :param ct: **[Out]** A buffer to store the resulting ciphertext.
    :param ct_sz: **[In]** The size of the ciphertext buffer.
    :param ss: **[Out]** A buffer to store the shared secret.
    :param ss_sz: **[In]** The size of the shared secret buffer.
    :param pk: **[In]** The public key.
    :param pk_sz: **[In]** The size of the public key.

Examples:

* Kyber512:

.. code:: c

    void CC_Kyber_512_encapsulate(uint8_t *ct, size_t ct_sz,
                                  uint8_t *ss, size_t ss_sz,
                                  const uint8_t *pk, size_t pk_sz);

* Kyber1024-90s:

.. code:: c

    void CC_Kyber_1024_90s_encapsulate(uint8_t *ct, size_t ct_sz,
                                       uint8_t *ss, size_t ss_sz,
                                       const uint8_t *pk, size_t pk_sz);

Decapsulate
^^^^^^^^^^^

To test a function that decapsulates with Kyber, its name must conform to the following convention:

.. code::

    CC_Kyber_<param set>_decapsulate

Its signature must be:

.. c:function:: int Kyber_decapsulate(\
    uint8_t *ss, size_t ss_sz,\
    const uint8_t *ct, size_t ct_sz,\
    const uint8_t *pk, size_t pk_sz)

    :param ss: **[Out]** A buffer to store the decapsulated shared secret.
    :param ss_sz: **[In]** The size of the shared secret buffer.
    :param ct: **[In]** The ciphertext to decapsulate.
    :param ct_sz: **[In]** The size of the ciphertext.
    :param sk: **[In]** The secret key.
    :param sk_sz: **[In]** The size of the secret key.

Examples:

* Kyber512:

.. code:: c

    void CC_Kyber_512_decapsulate(uint8_t *ss, size_t ss_sz,
                                  const uint8_t *ct, size_t ct_sz,
                                  const uint8_t *sk, size_t sk_sz);

* Kyber1024-90s:

.. code:: c

    void CC_Kyber_1024_90s_decapsulate(uint8_t *ss, size_t ss_sz,
                                       const uint8_t *ct, size_t ct_sz,
                                       const uint8_t *sk, size_t sk_sz);

----

.. [#] In the third round submission, the size of the shared secret is actually considered variable, but in the reference implementation it is defined as 32 bytes so we consider it fixed.
