AES
---

The functions to test AES implementations share the same parameters:

* ``mode`` is a **required** parameter. Its possible values are:
   * *Classic* modes: ``ECB``, ``CBC``, ``CBCPKCS7``, ``CFB8``, ``CFB128``, ``CTR``
   * *AEAD* modes: ``CCM``, ``GCM``

* ``key size`` is an **optional** parameter.  If omitted, the implementation is considered to support all three key sizes.  Its possible values are:
   * ``128``, ``192``, ``256``

Encrypt
^^^^^^^

To test a function that encrypts with AES, its name must conform to the following convention:

.. code::

   CC_AES_<mode>_[key size]_encrypt

Its signature must conform to either :c:func:`encrypt` or :c:func:`encrypt_aead` depending on the mode of operation:

.. c:function:: void encrypt(\
   uint8_t *buffer, size_t buffer_size,\
   const uint8_t *key, size_t key_size,\
   const uint8_t *iv, size_t iv_size)

   Encrypts a plaintext with AES using a classic mode of operation.

   :param buffer: **[In/Out]** A buffer containing the plaintext to encrypt, and where the ciphertext should be copied to.
   :param buffer_size: **[In]** The size of the buffer in bytes.
   :param key: **[In]** The symmetric key.
   :param key_size: **[In]** The size of the key in bytes. Even when specifying a key size, this argument is passed but can be safely ignored.
   :param iv: **[In]** The IV. NULL if no IV is used.
   :param iv_size: **[In]** The size of the IV in bytes. 0 if no IV is used.

.. c:function:: void encrypt_aead(\
   uint8_t *buffer, size_t buffer_size,\
   uint8_t *mac, size_t mac_size,\
   const uint8_t *key, size_t key_size,\
   const uint8_t *iv, size_t iv_size,\
   const uint8_t *aad, size_t aad_size)

   Encrypts a plaintext with AES using an authenticated mode of operation.

   :param buffer: **[In/Out]** A buffer containing the plaintext to encrypt, and where the ciphertext should be copied to.
   :param buffer_size: **[In]** The size of the buffer in bytes.
   :param mac: **[In/Out]** A buffer to return the MAC tag.
   :param mac_size: **[In]** The expected size of the MAC tag in bytes.
   :param key: **[In]** The symmetric key.
   :param key_size: **[In]** The size of the key in bytes. Even when specifying a key size this argument is passed but can be safely ignored.
   :param nonce: **[In]** The nonce.
   :param nonce_size: **[In]** The size of the nonce in bytes.
   :param aad: **[In]** The *optional* associated data. NULL if not used.
   :param aad_size: **[In]** The size of the associated data in bytes. 0 if not used.

Examples:

* AES-ECB:

.. code:: c

   void CC_AES_ECB_encrypt(uint8_t *buffer, size_t buffer_size,
                           const uint8_t *key, size_t key_size,
                           const uint8_t *iv, size_t iv_size) {
        struct AES_ctx ctx;
        AES_init_ctx(&ctx, key, key_size);
        AES_ECB_encrypt_buffer(&ctx, buffer, buffer_size);
   }

* AES-128-CBC:

.. code:: c

   void CC_AES_CBC_128_encrypt(uint8_t *buffer, size_t buffer_size,
                              const uint8_t *key, size_t key_size,
                              const uint8_t *iv, size_t iv_size);

* AES-CCM:

.. code:: c

   void CC_AES_CCM_encrypt(uint8_t *buffer, size_t buffer_size,
                          uint8_t *mac, size_t mac_size,
                          const uint8_t *key, size_t key_size,
                          const uint8_t *nonce, size_t nonce_size,
                          const uint8_t *aad, size_t aad_size);

* AES-256-GCM:

.. code:: c

   void CC_AES_GCM_256_encrypt(uint8_t *buffer, size_t buffer_size,
                              uint8_t *mac, size_t mac_size,
                              const uint8_t *key, size_t key_size,
                              const uint8_t *nonce, size_t nonce_size,
                              const uint8_t *aad, size_t aad_size);

Decrypt
^^^^^^^

To test a function that decrypts with AES, its name must conform to the following convention:

.. code::

   CC_AES_<mode>_[key size]_decrypt

Its signature must conform to either :c:func:`decrypt` or :c:func:`decrypt_aead` depending on the mode of operation:

.. c:function:: void decrypt(\
   uint8_t *buffer, size_t buffer_size,\
   const uint8_t *key, size_t key_size,\
   const uint8_t *iv, size_t iv_size)

   Decrypts a ciphertext with AES using a classic mode of operation.

   :param buffer: **[In/Out]** A buffer containing the ciphertext to decrypt, and where the plaintext should be copied to.
   :param buffer_size: **[In]** The size of the buffer in bytes.
   :param key: **[In]** The symmetric key.
   :param key_size: **[In]** The size of the key in bytes. Even when specifying a key size this argument is passed but can be safely ignored.
   :param iv: **[In]** The IV, NULL if no IV is used.
   :param iv_size: **[In]** The size of the IV in bytes, 0 if no IV is used.
   :param plaintext: **[Out]** A buffer to store the resulting plaintext. It has the same size as the ciphertext.


.. c:function:: int decrypt_aead(\
   uint8_t *buffer, size_t buffer_size,\
   const uint8_t *key, size_t key_size,\
   const uint8_t *ciphertext, size_t ciphertext_size,\
   const uint8_t *iv, size_t iv_size,\
   const uint8_t *aad, size_t aad_size,\
   const uint8_t *mac, size_t mac_size)

   Authenticates and decrypts a ciphertext with AES using an authenticated mode of operation.

   :param buffer: **[In/Out]** A buffer containing the ciphertext to decrypt, and where the plaintext should be copied to.
   :param buffer_size: **[In]** The size of the buffer in bytes.
   :param key: **[In]** The symmetric key.
   :param key_size: **[In]** The size of the key in bytes. Even when specifying a key size this argument is passed but can be safely ignored.
   :param nonce: **[In]** The nonce.
   :param nonce_size: **[In]** The size of the nonce in bytes.
   :param aad: **[In]** The *optional* associated data. NULL if not used.
   :param aad_size: **[In]** The size of the associated data in bytes. 0 if not used.
   :param mac: **[In]** The MAC tag to use to authenticate the ciphertext.
   :param mac_size: **[In]** The size of the MAC tag in bytes.
   :returns: A status value.
   :retval 0: OK.
   :retval -1: The MAC verification failed.

Examples:

* AES-ECB:

.. code:: c

   void CC_AES_ECB_decrypt(uint8_t *buffer, size_t buffer_size,
                          const uint8_t *key, size_t key_size,
                          const uint8_t *iv, size_t iv_size);

* AES-128-CBC:

.. code:: c

   void CC_AES_CBC_128_decrypt(uint8_t *buffer, size_t buffer_size,
                              const uint8_t *key, size_t key_size,
                              const uint8_t *iv, size_t iv_size);

* AES-CCM:

.. code:: c

   int CC_AES_CCM_decrypt(uint8_t *buffer, size_t buffer_size,
                          const uint8_t *key, size_t key_size,
                          const uint8_t *nonce, size_t nonce_size,
                          const uint8_t *aad, size_t aad_size,
                          const uint8_t *mac, size_t mac_size);

* AES-256-GCM:

.. code:: c

   int CC_AES_GCM_256_decrypt(uint8_t *buffer, size_t buffer_size,
                              const uint8_t *key, size_t key_size,
                              const uint8_t *nonce, size_t nonce_size,
                              const uint8_t *aad, size_t aad_size,
                              const uint8_t *mac, size_t mac_size);
