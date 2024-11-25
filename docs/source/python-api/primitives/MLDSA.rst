:tocdepth: 3

ML-DSA
======

How to use the :mod:`crypto_condor.primitives.MLDSA` module to test implementations of
:doc:`MLDSA </method/MLDSA>`.

.. currentmodule:: crypto_condor.primitives.MLDSA

Test signing
------------

.. autofunction:: test_sign

Test signature verification
---------------------------

.. autofunction:: test_verify

Parameters
----------

.. autoenum:: Paramset
   :members:

Protocols
---------

.. autoprotocol:: Sign

.. autoprotocol:: Verify

Test vectors
------------

The following section describes the internal test vectors classes, which are protobuf
Python classes.

.. hint::

   The autodoc extension can't properly document these clases so we include the
   ``.proto`` file to show the different fields each class has. IDEs should be able to
   use the included ``.pyi`` files to provide auto-completion and type checking.

.. class:: MldsaVectors

   Protobuf class that stores test vectors. See the description below.

.. literalinclude:: ../../../../crypto_condor/vectors/_mldsa/mldsa.proto
   :language: proto

