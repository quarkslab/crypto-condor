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
            case "SHA-224" | "SHA3-224" | "SHA-512/224":
                self._digest_size_ = 224
            case "SHA-256" | "SHA3-256" | "SHA-512/256":
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

    @classmethod
    def from_name(cls, name: str):
        """Returns a new instance from a name.

        Compact names such as sha256, sha3384 (SHA3-384) and sha512224 (SHA-512/224) are
        used for harness function names. This method returns the corresponding instance.

        Raises:
            ValueError:
                If the name is invalid.
        """
        match name:
            case "sha1" | "sha224" | "sha256" | "sha384" | "sha512":
                newname = name.replace("sha", "SHA-")
            case "sha3256" | "sha3384" | "sha3512":
                newname = name.replace("sha3", "SHA3-")
            case "sha512224":
                newname = "SHA-512/224"
            case "sha512256":
                newname = "SHA-512/256"
            case _:
                raise ValueError(f"Invalid hash name {name}")
        if newname not in cls:
            # Use name for the error message as that's what the user wrote.
            raise ValueError(f"{name} is not supported for HMAC")
        return cls(newname)
