:tocdepth: 3

HMAC
====

.. automodule:: crypto_condor.primitives.HMAC

.. currentmodule:: crypto_condor.primitives.HMAC

Parameters
----------

.. autoenum:: Hash

Protocols
---------

.. autoprotocol:: HMAC
    :member-order: bysource

.. autoprotocol:: HMAC_IUF
    :member-order: bysource

Main test
---------

.. autofunction:: test_hmac

Specific tests
--------------

.. autofunction:: test_digest_nist

.. autofunction:: test_digest_wycheproof

.. autofunction:: test_verify_nist

.. autofunction:: test_verify_wycheproof

Other functions
---------------

.. autofunction:: is_hmac_iuf

