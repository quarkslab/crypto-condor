:tocdepth: 3

SHA
===

.. currentmodule:: crypto_condor.primitives.SHA

How to use the :mod:`crypto_condor.primitives.SHA` module to test implementations of the
:doc:`SHA-1, SHA-2, and SHA-3 families of hash functions </method/SHA>`.

Supported parameters
--------------------

The supported algorithms are defined by the :enum:`Algorithm` enum.

Implementations can be either bit- or byte-oriented. To select an orientation use the
:enum:`Orientation` enum.

.. autoenum:: Algorithm

.. autoenum:: Orientation

Test an implementation directly
-------------------------------

.. autofunction:: test

Test the output of an implementation
------------------------------------

.. autofunction:: verify_file

Run a wrapper
-------------

.. note::

    Available wrappers are defined by :enum:`Wrapper`.

.. autofunction:: run_wrapper

.. autoenum:: Wrapper

Protocols
---------

.. autoprotocol:: HashFunction

