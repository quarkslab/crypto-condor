:tocdepth: 3

SHAKE
=====

.. currentmodule:: crypto_condor.primitives.SHAKE

How to use the :mod:`crypto_condor.primitives.SHAKE` module to test implementations of
SHAKE128 and SHAKE256.

Test an implementation
----------------------

.. autofunction:: test_digest

.. autofunction:: test_output_digest

.. autofunction:: test

Parameters
----------

This module can test implementations of both SHAKE128 and SHAKE256, as indicated by the
:enum:`Algorithm` enum.

.. autoenum:: Algorithm

Protocols
---------

.. autoprotocol:: Xof
