ChaCha20
--------

Encrypt
^^^^^^^

To test a function that encrypts with ChaCha20 only, its name must conform to the following convention:

.. code::

    CC_ChaCha20_encrypt

Its signature must be:

.. c:function:: void CC_ChaCha20_encrypt(\
    uint8_t *buffer, size_t buffer_size,\
    const uint8_t key[32],\
    const uint8_t *nonce, size_t nonce_size,\
    uint64_t init_counter)

    :param buffer: **[In/Out]** A buffer containing the plaintext to encrypt, and to store the resulting ciphertext.
    :param buffer_size: **[In]** The size of the buffer in bytes.
    :param key: **[In]** The 32-byte symmetric key.
    :param nonce: **[In]** The nonce.
    :param nonce_size: **[In]** The size of the nonce in bytes.
    :param init_counter: **[In]** An absolute position within the keystream in bytes to seek before encrypting.

Example:

.. code:: c

    void CC_ChaCha20_encrypt(uint8_t *buffer, size_t buffer_size,
                            const uint8_t key[32],
                            const uint8_t *nonce, size_t nonce_size,
                            uint64_t init_counter);

Decrypt
^^^^^^^

To test a function that decrypts with ChaCha20 only, its name must conform to the following convention:

.. code::

    CC_ChaCha20_decrypt

Its signature must be:

.. c:function:: void CC_ChaCha20_decrypt(\
    uint8_t *buffer, size_t buffer_size,\
    const uint8_t key[32],\
    const uint8_t *nonce, size_t nonce_size,\
    uint64_t init_counter)

    :param buffer: **[In/Out]** A buffer containing the ciphertext to decrypt, and to store the resulting plaintext.
    :param buffer_size: **[In]** The size of the buffer in bytes.
    :param key: **[In]** The 32-byte symmetric key.
    :param nonce: **[In]** The nonce.
    :param nonce_size: **[In]** The size of the nonce in bytes.
    :param init_counter: **[In]** An absolute position within the keystream in bytes to seek before decrypting.

Example:

.. code:: c

    void CC_ChaCha20_encrypt(uint8_t *buffer, size_t buffer_size,
                            const uint8_t key[32],
                            const uint8_t *nonce, size_t nonce_size,
                            uint64_t init_counter);

Encrypt with Poly1305
^^^^^^^^^^^^^^^^^^^^^

To test a function that encrypts with ChaCha20-Poly1305, its name must conform to the following convention:

.. code::

    CC_ChaCha20_Poly1305_encrypt

Its signature must be:

.. c:function:: void CC_ChaCha20_Poly1305_encrypt(\
    uint8_t *buffer, size_t buffer_size,\
    uint8_t mac[16],\
    const uint8_t key[32],\
    const uint8_t *nonce, size_t nonce_size,\
    const uint8_t *aad, size_t aad_size)

    :param buffer: **[In/Out]** A buffer containing the plaintext to encrypt, and to store the resulting ciphertext.
    :param buffer_size: **[In]** The size of the buffer in bytes.
    :param mac: **[Out]** A buffer to store the resulting 16-byte MAC tag.
    :param key: **[In]** The 32-byte symmetric key.
    :param nonce: **[In]** The nonce.
    :param nonce_size: **[In]** The size of the nonce in bytes.
    :param aad: **[In]** The *optional* associated data. NULL if not used.
    :param aad_size: **[In]** The size of the associated data. 0 if not used.

Example:

.. code:: c

    void CC_ChaCha20_Poly1305_encrypt(uint8_t *buffer, size_t buffer_size,
                                     uint8_t mac[16],
                                     const uint8_t key[32],
                                     const uint8_t *nonce, size_t nonce_size,
                                     const uint8_t *aad, size_t aad_size);

Decrypt with Poly1305
^^^^^^^^^^^^^^^^^^^^^

To test a function that decrypts with ChaCha20-Poly1305, its name must conform to the following convention:

.. code::

    CC_ChaCha20_Poly1305_decrypt

Its signature must be:

.. c:function:: int CC_ChaCha20_Poly1305_decrypt(\
    uint8_t *buffer, size_t buffer_size,\
    const uint8_t key[32],\
    const uint8_t *nonce, size_t nonce_size,\
    const uint8_t *aad, size_t aad_size,\
    const uint8_t mac[16])

    :param buffer: **[In/Out]** A buffer containing the ciphertext to decrypt, and to store the resulting plaintext. It is ignored if the function returns -2.
    :param buffer_size: **[In]** The size of the buffer in bytes.
    :param key: **[In]** The 32-byte symmetric key.
    :param nonce: **[In]** The nonce.
    :param nonce_size: **[In]** The size of the nonce in bytes.
    :param aad: **[In]** The *optional* associated data. NULL if not used.
    :param aad_size: **[In]** The size of the associated data. 0 if not used.
    :param mac: **[In]** The 16-byte MAC tag to verify.
    :returns: A status value.
    :retval 0: OK.
    :retval -1: The MAC verification failed.

Example:

.. code:: c

    int CC_ChaCha20_Poly1305_decrypt(uint8_t *buffer, size_t buffer_size,
                                     const uint8_t key[32],
                                     const uint8_t *nonce, size_t nonce_size,
                                     const uint8_t *aad, size_t aad_size,
                                     const uint8_t mac[16]);
