:tocdepth: 3

.. currentmodule:: crypto_condor.primitives.SLHDSA

SLH-DSA Python API
==================

How to use the :mod:`crypto_condor.primitives.SLHDSA` module to test
implementations of :doc:`SLH-DSA </method/SLHDSA>`.

Test signing
------------

.. autofunction:: test_sign

Test verifying
--------------

.. autofunction:: test_verify

Test sign-verify invariant
--------------------------

.. autofunction:: test_invariant

Parameters
----------

.. autoenum:: Paramset
   :members:

Protocols
---------

.. autoprotocol:: Keygen

.. autoprotocol:: Sign

.. autoprotocol:: Verify
