:tocdepth: 3

ECDSA
=====

.. currentmodule:: crypto_condor.primitives.ECDSA

How to use the :mod:`crypto_condor.primitives.ECDSA` module to test implementations of
:doc:`ECDSA </method/ECDSA>`.

Supported parameters
--------------------

To test ECDSA implementations you must choose an elliptic curve and a hash function. We
use enums to define the supported parameters: :enum:`Curve` and :enum:`Hash`.

Some functions require an indication of which key encoding to use: refer to
:enum:`KeyEncoding` and :enum:`PubKeyEncoding`.

.. autoenum:: Curve

.. autoenum:: Hash

.. autoenum:: KeyEncoding

.. autoenum:: PubKeyEncoding

Test a signature verification function
--------------------------------------

The following table describes whether a given curve is recommended by the ANSSI or the
NIST, and whether the combination of a curve and a hash function has NIST (**N**) and/or
Wycheproof (**W**) test vectors available.

.. list-table:: Test vectors for signature verification
   :header-rows: 1
   :stub-columns: 1
   :align: center
   :width: 100%

   * - Curve
     - ANSSI
     - NIST
     - SHA-256
     - SHA-384
     - SHA-512
     - SHA-3 256
     - SHA-3 384
     - SHA-3 512
   * - P-224
     - :red:`No`
     - :green:`Yes`
     - N+W
     - N
     - N+W
     - W
     - x
     - W
   * - P-256
     - :green:`Yes`
     - :green:`Yes`
     - N+W
     - N
     - N+W
     - W
     - x
     - W
   * - P-384
     - :green:`Yes`
     - :green:`Yes`
     - N
     - N+W
     - N+W
     - x
     - W
     - W
   * - P-521
     - :green:`Yes`
     - :green:`Yes`
     - N
     - N
     - N+W
     - x
     - x
     - W
   * - B-283
     - :green:`Yes`
     - :red:`No`
     - N
     - N
     - N
     - x
     - x
     - x
   * - B-409
     - :green:`Yes`
     - :red:`No`
     - N
     - N
     - N
     - x
     - x
     - x
   * - B-571
     - :green:`Yes`
     - :red:`No`
     - N
     - N
     - N
     - x
     - x
     - x
   * - FRP256v1
     - :green:`Yes`
     - :red:`No`
     - x
     - x
     - x
     - x
     - x
     - x

.. autofunction:: test_verify

Test a signing function
-----------------------

The table below indicates whether a given curve is recommended by the ANSSI or the NIST,
and whether the combination of a curve and a hash function has NIST (**N**) or
Wycheproof (**W**) test vectors available.

.. list-table:: Test vectors for signature generation
   :header-rows: 1
   :stub-columns: 1
   :align: center
   :width: 100%

   * - Curve
     - ANSSI
     - NIST
     - SHA-256
     - SHA-384
     - SHA-512
     - SHA-3 256
     - SHA-3 384
     - SHA-3 512
   * - P-224
     - :red:`No`
     - :green:`Yes`
     - N
     - N
     - N
     - x
     - x
     - x
   * - P-256
     - :green:`Yes`
     - :green:`Yes`
     - N
     - N
     - N
     - x
     - x
     - x
   * - P-384
     - :green:`Yes`
     - :green:`Yes`
     - N
     - N
     - N
     - x
     - x
     - x
   * - P-521
     - :green:`Yes`
     - :green:`Yes`
     - N
     - N
     - N
     - x
     - x
     - x
   * - B-283
     - :green:`Yes`
     - :red:`No`
     - N
     - N
     - N
     - x
     - x
     - x
   * - B-409
     - :green:`Yes`
     - :red:`No`
     - N
     - N
     - N
     - x
     - x
     - x
   * - B-571
     - :green:`Yes`
     - :red:`No`
     - N
     - N
     - N
     - x
     - x
     - x
   * - FRP256v1
     - :green:`Yes`
     - :red:`No`
     - x
     - x
     - x
     - x
     - x
     - x

.. autofunction:: test_sign

Test signing then verifying
---------------------------

.. autofunction:: test_sign_then_verify

Test a function generating key pairs
------------------------------------

.. autofunction:: test_key_pair_gen

Verify a file of signatures
---------------------------

.. autofunction:: verify_file

Run a wrapper
-------------

.. note::

    Available wrappers are defined by :enum:`Wrapper`.

.. autofunction:: run_wrapper

.. autoenum:: Wrapper

Protocols
---------

.. autoprotocol:: Verify

.. autoprotocol:: Sign

.. autoprotocol:: KeyGen

