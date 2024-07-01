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

import logging
from importlib import resources

import attrs
import strenum
from google.protobuf.message import DecodeError

from crypto_condor.vectors._HMAC.HMAC_pb2 import HmacNistVectors, HmacWycheproofVectors

# --------------------------- Module --------------------------------------------------

logger = logging.getLogger(__name__)


# --------------------------- Enums ---------------------------------------------------


class Hash(strenum.StrEnum):
    """A hash function that can be used with HMAC."""

    def __init__(self, value):
        """Override __init__ to add custom properties."""
        self._value_ = value
        match value:
            case "SHA-1" | "SHA-224" | "SHA-256" | "SHA-384" | "SHA-512":
                self._nist_ = True
                self._wycheproof_ = True
            case "SHA3-224" | "SHA3-256" | "SHA3-384" | "SHA3-512":
                self._nist_ = False
                self._wycheproof_ = True
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
    def nist(self) -> bool:
        """Returns True if there are NIST vectors for the hash function."""
        return self._nist_

    @property
    def wycheproof(self) -> bool:
        """Returns True if there are Wycheproof vectors for this hash function."""
        return self._wycheproof_

    @property
    def digest_size(self) -> int:
        """Returns the size of the digest in bits."""
        return self._digest_size_

    SHA_1 = "SHA-1"
    SHA_224 = "SHA-224"
    SHA_256 = "SHA-256"
    SHA_384 = "SHA-384"
    SHA_512 = "SHA-512"
    SHA3_224 = "SHA3-224"
    SHA3_256 = "SHA3-256"
    SHA3_384 = "SHA3-384"
    SHA3_512 = "SHA3-512"


# --------------------------- Exceptions ----------------------------------------------


class HmacVectorsError(Exception):
    """Exception for HMAC vectors."""

    pass


# --------------------------- Vectors -------------------------------------------------


@attrs.define(frozen=True)
class HmacVectors:
    """A class to load HMAC test vectors.

    Use :meth:`load` to instantiate.

    Args:
        hash_function: The hash function used by the HMAC implementation to test.
        nist: NIST vectors, if available.
        wycheproof: Wycheproof vectors, if available.
    """

    hash_function: Hash
    nist: HmacNistVectors | None
    wycheproof: HmacWycheproofVectors | None

    @classmethod
    def load(cls, hash_function: Hash):
        """Loads test vectors for a given hash function.

        Args:
            hash_function: The hash function used by the HMAC implementation.

        Returns:
            An instance of :class:`HmacVectors` with NIST and Wycheproof vectors loaded,
            if available.

        Raises:
            HmacVectorsError: If an error occurred when loading the vectors.
        """
        vectors_dir = resources.files("crypto_condor") / "vectors/_HMAC"

        if hash_function.nist:
            vectors_file = vectors_dir / f"dat/hmac_nist_{str(hash_function)}.dat"
            nist_vectors = HmacNistVectors()
            try:
                nist_vectors.ParseFromString(vectors_file.read_bytes())
            except DecodeError as error:
                logger.exception("Error decoding HMAC test vectors")
                raise HmacVectorsError("Could not load HMAC vectors") from error
        else:
            nist_vectors = None

        if hash_function.wycheproof:
            vectors_file = vectors_dir / f"dat/hmac_wp_{str(hash_function)}.dat"
            wycheproof_vectors = HmacWycheproofVectors()
            try:
                wycheproof_vectors.ParseFromString(vectors_file.read_bytes())
            except OSError as error:
                logger.exception("Error opening vectors file %s", str(vectors_file))
                raise HmacVectorsError("Could not load HMAC vectors") from error
            except DecodeError as error:
                logger.exception("Error decoding HMAC test vectors")
                raise HmacVectorsError("Could not load HMAC vectors") from error
        else:
            wycheproof_vectors = None

        return cls(hash_function, nist_vectors, wycheproof_vectors)
