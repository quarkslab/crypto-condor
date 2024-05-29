:tocdepth: 3

HMAC
====

.. automodule:: crypto_condor.primitives.HMAC

.. currentmodule:: crypto_condor.primitives.HMAC

Parameters
----------

.. autoenum:: Hash

Protocols
---------

.. autoprotocol:: HMAC
    :member-order: bysource

.. autoprotocol:: HMAC_IUF
    :member-order: bysource

Main test
---------

.. autofunction:: test_hmac

Specific tests
--------------

.. autofunction:: test_digest_nist

.. autofunction:: test_digest_wycheproof

.. autofunction:: test_verify_nist

.. autofunction:: test_verify_wycheproof

Other functions
---------------

.. autofunction:: is_hmac_iuf

Vectors
-------

.. automodule:: crypto_condor.vectors.HMAC

.. autoclass:: crypto_condor.vectors.HMAC.HmacVectors
   :members:

Internal vectors
----------------

The following section describes the internal test vectors classes, which are protobuf
Python classes.

.. hint::

   The autodoc extension can't properly document these clases so we include the
   ``.proto`` file to show the different fields each class has. IDEs should be able to
   use the included ``.pyi`` files to provide auto-completion and type checking.

.. currentmodule:: crypto_condor.vectors._HMAC.HMAC_pb2

.. class:: HmacNistVectors

   Protobuf class to store NIST vectors, see below.

.. class:: HmacWycheproofVectors

   Protobuf class to store Wycheproofvectors, see below.

.. literalinclude:: ../../../../crypto_condor/vectors/_HMAC/HMAC.proto
   :language: proto

