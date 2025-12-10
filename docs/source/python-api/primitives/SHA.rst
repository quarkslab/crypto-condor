:tocdepth: 3

SHA
===

.. currentmodule:: crypto_condor.primitives.SHA

How to use the :mod:`crypto_condor.primitives.SHA` module to test implementations of the
:doc:`SHA-1, SHA-2, and SHA-3 families of hash functions </method/SHA>`.

Supported parameters
--------------------

The supported algorithms are defined by the :enum:`Hash` enum.

.. autoenum:: Hash

Test an implementation directly
-------------------------------

.. autofunction:: test_digest

.. autofunction:: test

Test the output of an implementation
------------------------------------

.. autofunction:: test_output_digest

.. autofunction:: verify_file

Protocols
---------

.. autoprotocol:: HashFunction

