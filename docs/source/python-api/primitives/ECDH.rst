:tocdepth: 3

ECDH
====

.. automodule:: crypto_condor.primitives.ECDH

.. currentmodule:: crypto_condor.primitives.ECDH

Test implementations
--------------------

.. autofunction:: test_exchange

Parameters
----------

.. autoenum:: Curve
   :members:

Protocols
---------

.. autoprotocol:: ECDH

Vectors
-------

.. autoclass:: EcdhVectors
   :members:

Wrappers
--------

.. autoenum:: Wrapper

.. autofunction:: run_wrapper

Internal tests
--------------

.. autofunction:: test_exchange_nist

.. autofunction:: test_exchange_wycheproof

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

