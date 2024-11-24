:tocdepth: 3

ML-KEM
======

How to use the :mod:`crypto_condor.primitives.MLKEM` module to test implementations of
:doc:`MLKEM </method/MLKEM>`.

.. currentmodule:: crypto_condor.primitives.MLKEM

Test encapsulation
------------------

.. autofunction:: test_encaps

.. autofunction:: test_output_encaps

Test decapsulation
------------------

.. autofunction:: test_decaps

Parameters
----------

.. autoenum:: Paramset
   :members:

Protocols
---------

.. autoprotocol:: Encaps

.. autoprotocol:: Decaps

Test vectors
------------

The following section describes the internal test vectors classes, which are protobuf
Python classes.

.. hint::

   The autodoc extension can't properly document these clases so we include the
   ``.proto`` file to show the different fields each class has. IDEs should be able to
   use the included ``.pyi`` files to provide auto-completion and type checking.

.. class:: MlkemVectors

   Protobuf class that stores test vectors. See the description below.

.. literalinclude:: ../../../../crypto_condor/vectors/_mlkem/mlkem.proto
   :language: proto

