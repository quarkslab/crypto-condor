ML-KEM
------

In ML-KEM, the size of the public and private keys, the ciphertext, and shared secret is
fixed. These values are still passed to the implementation, but if the implementation
you are testing doesn't require them, that may be the reason why.

.. csv-table:: Parameter sets and object sizes (in bytes)
    :header-rows: 1
    :stub-columns: 1

    "Parameter set", "Private key", "Public Key", "Ciphertext", "Shared secret"
    ``512``, 1632, 800, 768, 32
    ``768``, 2400, 1184, 1088, 32
    ``1024``, 3168, 1568, 1568, 32

Encapsulation
^^^^^^^^^^^^^

To test a function that encapsulates with ML-KEM, its name must conform to the following convention:

.. code::

    CC_MLKEM_<param set>_encaps

Its signature must be:

.. c:function:: void MLKEM_encaps(\
    uint8_t *ct, size_t ctlen,\
    uint8_t *ss, size_t sslen,\
    const uint8_t *pk, size_t pklen)

    :param ct: **[Out]** A buffer to store the resulting ciphertext.
    :param ctlen: **[In]** The size of the ciphertext buffer.
    :param ss: **[Out]** A buffer to store the shared secret.
    :param sslen: **[In]** The size of the shared secret buffer.
    :param pk: **[In]** The public key.
    :param pklen: **[In]** The size of the public key.

Examples:

* ML-KEM-512:

.. code:: c

    void CC_MLKEM_512_encaps(uint8_t *ct, size_t ctlen,
                             uint8_t *ss, size_t sslen,
                             const uint8_t *pk, size_t pklen);

Decapsulation
^^^^^^^^^^^^^

To test a function that decapsulates with ML-KEM, its name must conform to the following convention:

.. code::

    CC_MLKEM_<param set>_decaps

Its signature must be:

.. c:function:: int MLKEM_decaps(\
    uint8_t *ss, size_t sslen,\
    const uint8_t *ct, size_t ctlen,\
    const uint8_t *pk, size_t pklen)

    :param ss: **[Out]** A buffer to store the decapsulated shared secret.
    :param sslen: **[In]** The size of the shared secret buffer.
    :param ct: **[In]** The ciphertext to decapsulate.
    :param ctlen: **[In]** The size of the ciphertext.
    :param sk: **[In]** The secret key.
    :param sklen: **[In]** The size of the secret key.

Examples:

* ML-KEM-512:

.. code:: c

    void CC_MLKEM_512_decaps(uint8_t *ss, size_t sslen,
                             const uint8_t *ct, size_t ctlen,
                             const uint8_t *sk, size_t sklen);

