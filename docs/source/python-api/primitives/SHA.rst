:tocdepth: 3

SHA
===

.. currentmodule:: crypto_condor.primitives.SHA

How to use the :mod:`crypto_condor.primitives.SHA` module to test implementations of the
:doc:`SHA-1, SHA-2, and SHA-3 families of hash functions </method/SHA>`.

Supported parameters
--------------------

The supported algorithms are defined by the :enum:`Algorithm` enum.

.. autoenum:: Algorithm

Test an implementation directly
-------------------------------

.. autofunction:: test

Test the output of an implementation
------------------------------------

.. autofunction:: verify_file

Test a wrapper
--------------

.. autofunction:: test_wrapper

.. autofunction:: test_wrapper_python

Protocols
---------

.. autoprotocol:: HashFunction

