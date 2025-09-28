:tocdepth: 3

.. currentmodule:: crypto_condor.primitives.ChaCha20

ChaCha20
========

How to use the :mod:`crypto_condor.primitives.ChaCha20` module to test implementations
of :doc:`ChaCha20 </method/ChaCha20>`.

Test ChaCha20
-------------

.. autofunction:: test_encrypt

.. autofunction:: test_decrypt

.. autofunction:: test_output_encrypt

.. autofunction:: test_output_decrypt

Test ChaCha20-Poly1305
-----------------------------

.. autofunction:: test_encrypt_poly

.. autofunction:: test_decrypt_poly

.. autofunction:: test_output_encrypt_poly

.. autofunction:: test_output_decrypt_poly

Protocols
---------

.. autoprotocol:: Encrypt

.. autoprotocol:: Decrypt

.. autoprotocol:: EncryptPoly

.. autoprotocol:: DecryptPoly
