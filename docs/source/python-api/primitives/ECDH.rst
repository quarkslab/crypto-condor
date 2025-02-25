:tocdepth: 3

ECDH
====

.. automodule:: crypto_condor.primitives.ECDH

.. currentmodule:: crypto_condor.primitives.ECDH

Test implementations
--------------------

There are two types of test vectors available: those that provide the peer's public key
as the encoded coordinates of the point and those that provide it as a X.509
`SubjectPublicKeyInfo` field. Since the function signature is different, there is one
test for each type.

.. autofunction:: test_exchange_point

.. autofunction:: test_exchange_x509

.. autofunction:: test_exchange

.. autofunction:: test_exchange_nist

.. autofunction:: test_exchange_wycheproof

Parameters
----------

.. autoenum:: Curve
   :members:

Protocols
---------

.. autoprotocol:: ExchangePoint

.. autoprotocol:: ExchangeX509

.. autoprotocol:: ECDH

Internal runners
----------------

.. autofunction:: run_wrapper_python

Internal vectors
----------------

The following section describes the internal test vectors classes, which are protobuf
Python classes.

.. hint::

   The autodoc extension can't properly document these clases so we include the
   ``.proto`` file to show the different fields each class has. IDEs should be able to
   use the included ``.pyi`` files to provide auto-completion and type checking.

.. currentmodule:: crypto_condor.vectors._ecdh.ecdh_pb2

.. literalinclude:: ../../../../crypto_condor/vectors/_ecdh/ecdh.proto
   :language: proto

