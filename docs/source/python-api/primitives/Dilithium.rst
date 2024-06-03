:tocdepth: 3

Dilithium
=========

.. include:: ../../_static/dilithium-vectors-warning.rst.txt

.. currentmodule:: crypto_condor.primitives.Dilithium

Supported parameters
--------------------

Dilithium has three parameter sets: these are supported and defined by :enum:`Paramset`.

.. autoenum:: Paramset

Test a signing function
-----------------------

.. autofunction:: test_sign

Test a verifying function
-------------------------

.. autofunction:: test_verify

Run a wrapper
-------------

.. note::

   Available wrappers are defined by :enum:`Wrapper`.

.. autofunction:: run_wrapper

.. autoenum:: Wrapper

Protocols
---------

.. autoprotocol:: Sign

.. autoprotocol:: Verify

