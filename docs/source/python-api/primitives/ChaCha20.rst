:tocdepth: 3

.. currentmodule:: crypto_condor.primitives.ChaCha20

ChaCha20
========

How to use the :mod:`crypto_condor.primitives.ChaCha20` module to test implementations
of :doc:`ChaCha20 </method/ChaCha20>`.

Supported parameters
--------------------

There are two supported modes of operation: ChaCha20 on its own and the construction
with Poly1305. They are defined by the :enum:`Mode` enum.

Two operations can be performed: :attr:`~Operation.ENCRYPT` and
:attr:`~Operation.DECRYPT`. These are defined by the :enum:`Operation` enum.

.. autoenum:: Mode

.. autoenum:: Operation

Test an implementation directly
-------------------------------

.. autofunction:: test

Test the output of an implementation
------------------------------------

.. note::

    From the CLI you can test the file with the ``test output ChaCha20`` command.

.. autofunction:: verify_file

Run a wrapper
-------------

.. note::

    Available wrappers are defined by the :enum:`Wrapper` enum.

.. autofunction:: run_wrapper

.. autoenum:: Wrapper

Protocols
---------

.. autoprotocol:: Encrypt

.. autoprotocol:: Decrypt

