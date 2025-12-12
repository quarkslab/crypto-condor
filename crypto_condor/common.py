"""Common objects for |cc|.

Common hash function
--------------------

.. autoenum:: CommonHash
    :members:

Common elliptic curves
----------------------

.. autoenum:: CommonCurve
    :members:

TestU01 constants
-----------------

.. autodata:: TESTU01_MIN

.. autodata:: TESTU01_REC
"""

import hashlib

from strenum import StrEnum

# -------------------------------------------------------------------------------------
# TestU01
# -------------------------------------------------------------------------------------

TESTU01_MIN = 100_000
"""Minimum number of bytes for TestU01.

100KB is the minimum size required to run most (but not all) of TestU01 tests. As such,
it is enforced as the minimum size that can be tested using |cc|.
"""
TESTU01_REC = 10_000_000
"""Recommended minimum number of bytes for TestU01.

Starting with 10MB, all tests can be executed, so this is the size that should be used
as a default argument.
"""

# -------------------------------------------------------------------------------------
# CommonHash
# -------------------------------------------------------------------------------------


class CommonHash(StrEnum):
    """Available hash functions.

    CommonHash only defines methods and not enum members. This allows primitives to
    inherit generic methods from it, while defining which hash functions can actually be
    used with that primitive. For example, to create an enum that only accepts SHA-3:

    >>> from crypto_condor.common import CommonHash
    >>> class Hash(CommonHash):
    ...     SHA3_224 = "SHA3-224"
    ...     SHA3_256 = "SHA3-256"
    ...     SHA3_384 = "SHA3-384"
    ...     SHA3_512 = "SHA3-512"
    >>> assert Hash.from_name("sha3256") == Hash.SHA3_256

    Methods are valid for SHA-1 and the SHA-2 and SHA-3 families:

    .. code::

        SHA_1 = "SHA-1"
        SHA_224 = "SHA-224"
        SHA_256 = "SHA-256"
        SHA_384 = "SHA-384"
        SHA_512 = "SHA-512"
        SHA_512_224 = "SHA-512/224"
        SHA_512_256 = "SHA-512/256"
        SHA3_224 = "SHA3-224"
        SHA3_256 = "SHA3-256"
        SHA3_384 = "SHA3-384"
        SHA3_512 = "SHA3-512"

    Harnesses use the name of functions to indicate certain parameters, such as the hash
    function used. To simplify the parsing of function names, parameters should not
    include underscores, as they are used to separate the parameters themselves. These
    are the compact names accepted by ``CommonHash``:

    .. code::

        SHA_1 = "sha1"
        SHA_224 = "sha224"
        SHA_256 = "sha256"
        SHA_384 = "sha384"
        SHA_512 = "sha512"
        SHA_512_224 = "sha512224"
        SHA_512_256 = "sha512256"
        SHA3_224 = "sha3224"
        SHA3_256 = "sha3256"
        SHA3_384 = "sha3384"
        SHA3_512 = "sha3512"


    :meth:`from_name` will parse any valid hash function, but will raise `ValueError`
    if the hash function is not in the derived enum.
    """

    def __init__(self, value: str):
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
        self._sha3_ = value.startswith("SHA3-")
        self._harness_name_ = value.lower().replace("-", "").replace("/", "")

    @property
    def digest_size(self) -> int:
        """Returns the size of the digest in bits."""
        return self._digest_size_

    @property
    def sha3(self) -> bool:
        """True if the algorithm is a SHA-3 algorithm."""
        return self._sha3_

    @property
    def harness_name(self) -> str:
        """Returns the name of the hash function as used in harnesses."""
        return self._harness_name_

    @classmethod
    def from_name(cls, name: str):
        """Returns a new instance from a harness name.

        Compact names such as ``sha256``, ``sha3384`` (SHA3-384) and ``sha512224``
        (SHA-512/224) are used for harness function names. This method returns the
        corresponding instance.

        Raises:
            ValueError:
                If the name is invalid or if the hash function is not a member of the
                current enum.
        """
        match name:
            case "sha1" | "sha224" | "sha256" | "sha384" | "sha512":
                newname = name.replace("sha", "SHA-")
            case "sha3224" | "sha3256" | "sha3384" | "sha3512":
                newname = name.replace("sha3", "SHA3-")
            case "sha512224":
                newname = "SHA-512/224"
            case "sha512256":
                newname = "SHA-512/256"
            case _:
                raise ValueError(f"Invalid hash name {name}")
        if newname not in cls:
            # The hash function exists but it's not part of that primitive's enum.
            raise ValueError(
                f"{name} ({newname}) is not supported by the current primitive"
            )
        return cls(newname)

    def digest(self, data: bytes) -> bytes:
        """Hashes ``data`` with hashlib."""
        match str(self):
            case "SHA-1" | "SHA-224" | "SHA-256" | "SHA-384" | "SHA-512":
                h = getattr(hashlib, self.harness_name)
                return h(data).digest()
            case "SHA3-224" | "SHA3-256" | "SHA3-384" | "SHA3-512":
                h = getattr(hashlib, self.harness_name.replace("sha3", "sha3_"))
                return h(data).digest()
            case "SHA-512/224":
                return hashlib.new("sha512_224", data).digest()
            case "SHA-512/256":
                return hashlib.new("sha512_256", data).digest()
            case _:
                raise ValueError()  # To appease mypy.


# -------------------------------------------------------------------------------------
# CommonCurve
# -------------------------------------------------------------------------------------


class CommonCurve(StrEnum):
    """Available elliptic curves.

    CommonCurve, like :enum:`CommonHash`, only defines methods and not enum members.
    This allows other classes to inherit the methods while defining their own set of
    supported curves.

    For example, to create an enum that only allows NIST P-curves:

    >>> from crypto_condor.common import CommonCurve
    >>> class Curve(CommonCurve):
    ...     P224 = "P-224"
    ...     P256 = "P-256"
    ...     P384 = "P-384"
    ...     P521 = "P-521"
    >>> assert Curve.from_name("p256") == Curve.P256

    The following curves are supported:

    .. code:: Python

        P224 = "P-224"
        P256 = "P-256"
        P384 = "P-384"
        P521 = "P-521"
        B283 = "B-283"
        B409 = "B-409"
        B571 = "B-571"
        SECP256K1 = "secp256k1"
        BRAINPOOLP256R1 = "brainpoolP256r1"
        BRAINPOOLP384R1 = "brainpoolP384r1"
        BRAINPOOLP512R1 = "brainpoolP512r1"

    Harnesses use compact names, with no capitalisation or symbols:

    .. code:: Python

        P224 = "p224"
        P256 = "p256"
        P384 = "p384"
        P521 = "p521"
        B283 = "b283"
        B409 = "b409"
        B571 = "b571"
        SECP256K1 = "secp256k1"
        BRAINPOOLP256R1 = "brainpoolp256r1"
        BRAINPOOLP384R1 = "brainpoolp384r1"
        BRAINPOOLP512R1 = "brainpoolp512r1"

    :meth:`from_name` will parse any valid curve but will raise `ValueError` if the
    curve is not in the derived enum.
    """

    def __init__(self, value):
        """Override __init__ to add custom properties."""
        self._value_ = value
        match value:
            case "P-224" | "P-256" | "P-384" | "P-521":
                self._key_size_ = int(value[2:])
            case "secp256k1":
                self._key_size_ = 256
            case "brainpoolP256r1" | "brainpoolP384r1" | "brainpoolP512r1":
                self._key_size_ = int(value[10:13])
            case "B-283" | "B-409" | "B-571":
                self._key_size_ = int(value[2:])
            case _:
                raise ValueError(f"Unexpected enum value {value}")
        self._harness_name_ = value.lower().replace("-", "")

    @property
    def key_size(self) -> int:
        """Returns the size of the keys in bits."""
        return self._key_size_

    @property
    def harness_name(self) -> str:
        """Returns the name of the hash function as used in harnesses."""
        return self._harness_name_

    @classmethod
    def from_name(cls, name: str):
        """Returns a new instance from a harness name.

        See the description of :enum:`CommonCurve` for a list of valid names.

        Raises:
            ValueError:
                If the name is invalid or if the curve is not a member of the current
                enum.
        """
        match name:
            case "p224" | "p256" | "p384" | "p521":
                newname = name.replace("p", "P-")
            case "secp224r1" | "secp256r1" | "secp384r1" | "secp521r1":
                # Undocumented valid name, mainly for parsing test vectors.
                newname = "P-" + name.removeprefix("secp").removesuffix("r1")
            case "b283" | "b409" | "b571":
                newname = name.replace("b", "B-")
            case "brainpoolp256r1" | "brainpoolp384r1" | "brainpoolp512r1":
                newname = name.replace("lp", "lP")
            case "secp256k1":
                newname = name
            case _:
                raise ValueError(f"Invalid curve name: {name}")
        if newname not in cls:
            raise ValueError(
                f"{name} ({newname}) is not supported by the current primitive"
            )
        return cls(newname)
