"""HMAC test vectors.

There are `NIST
<https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/message-authentication>`_
and `Wycheproof <https://github.com/C2SP/wycheproof/tree/master/testvectors>`_ test
vectors available. These are parametrized by the hash function used with HMAC. Not all
hash functions are covered by both sources:

.. csv-table:: HMAC test vectors
    :header-rows: 1
    :stub-columns: 1

    "Hash function", "NIST", "Wycheproof"
    "SHA-1", :green:`Y`, :green:`Y`
    "SHA-224", :green:`Y`, :green:`Y`
    "SHA-256", :green:`Y`, :green:`Y`
    "SHA-384", :green:`Y`, :green:`Y`
    "SHA-512", :green:`Y`, :green:`Y`
    "SHA3-224", :red:`N`, :green:`Y`
    "SHA3-256", :red:`N`, :green:`Y`
    "SHA3-384", :red:`N`, :green:`Y`
    "SHA3-512", :red:`N`, :green:`Y`
"""

from crypto_condor.common import CommonHash


class Hash(CommonHash):
    """Available hash functions for HMAC."""

    SHA_1 = "SHA-1"
    SHA_224 = "SHA-224"
    SHA_256 = "SHA-256"
    SHA_384 = "SHA-384"
    SHA_512 = "SHA-512"
    SHA3_224 = "SHA3-224"
    SHA3_256 = "SHA3-256"
    SHA3_384 = "SHA3-384"
    SHA3_512 = "SHA3-512"
