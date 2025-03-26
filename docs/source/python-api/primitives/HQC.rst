:tocdepth: 3

.. currentmodule:: crypto_condor.primitives.HQC

HQC
===

How to use the :mod:`crypto_condor.primitives.HQC` module to test implementations of
:doc:`HQC </method/HQC>`.

Test encapsulation
------------------

.. attention::

   Testing encapsulation requires a reference implementation to decapsulate the
   ciphertexts, as encapsulation is a non-deterministic operation. We are working on
   integrating one.

Test decapsulation
------------------

.. autofunction:: test_decaps

Test the encapsulation-decapsulation invariant
----------------------------------------------

.. autofunction:: test_invariant

Parameters
----------

.. autoenum:: Paramset
   :members:

Protocols
---------

.. autoprotocol:: Encaps

.. autoprotocol:: Decaps
