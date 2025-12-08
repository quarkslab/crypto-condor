:tocdepth: 3

ECDSA
=====

How to use the :mod:`crypto_condor.primitives.ECDSA` module to test implementations of
:doc:`ECDSA </method/ECDSA>`.

.. currentmodule:: crypto_condor.primitives.ECDSA

Test signing
------------

.. autofunction:: test_sign

Test verifying
--------------

.. autofunction:: test_verify

Test signing and verifying
--------------------------

.. autofunction:: test_sign_verify_invariant

Test key pair generation
------------------------

.. autofunction:: test_keygen

.. autofunction:: test_key_pair_gen

Test signatures from a file
---------------------------

.. autofunction:: test_output_sign

.. autofunction:: verify_file

Parameters
----------

To test ECDSA implementations you must choose an elliptic curve and a hash function. We
use enums to define the supported parameters: :enum:`Curve` and :enum:`Hash`.

Some functions require an indication of which key encoding to use: refer to
:enum:`KeyEncoding` and :enum:`PubKeyEncoding`.

.. autoenum:: Curve

.. autoenum:: Hash

.. autoenum:: KeyEncoding
   :members:

.. autoenum:: PubKeyEncoding
   :members:

Protocols
---------

.. autoprotocol:: Sign

.. autoprotocol:: Verify

.. autoprotocol:: Keygen

Test vectors
------------

The following tables describe the test vectors available for each combination of
elliptic curve and hash function. :green:`C` denotes compliance, :blue:`R` resilience.

.. csv-table:: Test vector types for signing
   :file: ../../../../crypto_condor/vectors/_ecdsa/ecdsa_siggen.csv
   :header-rows: 1
   :stub-columns: 1
   :width: 100%
   :align: center

.. csv-table:: Test vector types for verifying
   :file: ../../../../crypto_condor/vectors/_ecdsa/ecdsa_sigver.csv
   :header-rows: 1
   :stub-columns: 1
   :align: center
   :width: 100%

