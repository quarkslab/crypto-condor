:tocdepth: 3

SHAKE
=====

.. currentmodule:: crypto_condor.primitives.SHAKE

How to use the :mod:`crypto_condor.primitives.SHAKE` module to test implementations of
SHAKE128 and SHAKE256.

Supported parameters
--------------------

This module can test implementations of both SHAKE128 and SHAKE256, as indicated by the
:enum:`Algorithm` enum.

Implementations can be either bit- or byte-oriented. To select an orientation use the
:enum:`Orientation` enum.

.. autoenum:: Algorithm

.. autoenum:: Orientation

Test an implementation directly
-------------------------------

.. autofunction:: test

Run a wrapper
-------------

.. note::

   Available wrappers are defined by :enum:`Wrapper`.

.. autofunction:: run_wrapper

.. autoenum:: Wrapper

Protocols
---------

.. autoprotocol:: Xof

