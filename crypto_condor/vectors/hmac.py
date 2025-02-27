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

import strenum


class Hash(strenum.StrEnum):
    """A hash function that can be used with HMAC."""

    SHA_1 = "SHA-1"
    SHA_224 = "SHA-224"
    SHA_256 = "SHA-256"
    SHA_384 = "SHA-384"
    SHA_512 = "SHA-512"
    SHA3_224 = "SHA3-224"
    SHA3_256 = "SHA3-256"
    SHA3_384 = "SHA3-384"
    SHA3_512 = "SHA3-512"

    def __init__(self, value):
        """Override __init__ to add custom properties."""
        self._value_ = value
        match value:
            case "SHA-1":
                self._digest_size_ = 160
            case "SHA-224" | "SHA3-224":
                self._digest_size_ = 224
            case "SHA-256" | "SHA3-256":
                self._digest_size_ = 256
            case "SHA-384" | "SHA3-384":
                self._digest_size_ = 384
            case "SHA-512" | "SHA3-512":
                self._digest_size_ = 512

    @property
    def digest_size(self) -> int:
        """Returns the size of the digest in bits."""
        return self._digest_size_

    @classmethod
    def from_funcname(cls, parts: list[str]):
        """Returns enum member from wrapper or harness hash name."""
        if not parts[0].startswith(("sha", "SHA")):
            raise ValueError(f"Invalid name {'_'.join(parts)}")
        if len(parts) == 1:
            return cls(f"SHA-{parts[0][3:]}")
        elif len(parts) == 2:
            return cls(f"SHA3-{parts[1]}")
        else:
            raise ValueError(f"Invalid name {'_'.join(parts)}")
