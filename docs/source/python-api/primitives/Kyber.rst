:tocdepth: 3

Kyber
=====

.. currentmodule:: crypto_condor.primitives.Kyber

Supported parameters
--------------------

Kyber has six parameter sets: these are supported and defined by :enum:`Paramset`.

.. autoenum:: Paramset

Test an encapsulation function
------------------------------

.. autofunction:: test_encapsulate

Test a decapsulation function
-----------------------------

.. autofunction:: test_decapsulate

Run a wrapper
-------------

.. note::

   Available wrappers are defined by :enum:`Wrapper`.

.. autofunction:: run_wrapper

.. autoenum:: Wrapper

Protocols
---------

.. autoprotocol:: Encapsulate

.. autoprotocol:: Decapsulate

