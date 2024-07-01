"""Test vectors for SHA and SHAKE."""

import logging
from importlib import resources

import attrs
import strenum
from google.protobuf import message

from crypto_condor.vectors._sha.sha_pb2 import (
    ShaMonteCarloNistVectors,
    ShaNistVectors,
)

logger = logging.getLogger(__name__)


# --------------------------- Enums ---------------------------------------------------


class Algorithm(strenum.StrEnum):
    """Supported hash algorithms."""

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

    @property
    def digest_size(self) -> int:
        """Returns the size of the digest in bits."""
        return self._digest_size_

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


class Orientation(strenum.StrEnum):
    """Orientation of the implementation."""

    BIT = "bit"
    BYTE = "byte"


_SHA_HASH_NAMES = {
    "SHA-1": "sha1",
    "SHA-224": "sha224",
    "SHA-256": "sha256",
    "SHA-384": "sha384",
    "SHA-512": "sha512",
    "SHA-512/224": "sha512_224",
    "SHA-512/256": "sha512_256",
    "SHA3-224": "sha3_224",
    "SHA3-256": "sha3_256",
    "SHA3-384": "sha3_384",
    "SHA3-512": "sha3_512",
}
"""Mapping of hash algorithm names to test vector files.

Likely to change, for a list of supported functions see :enum:`HashAlgorithm`.
"""


# --------------------------- Exceptions ----------------------------------------------


class ShaVectorsError(Exception):
    """Exception for errors when loading vectors."""

    pass


# --------------------------- Vectors -------------------------------------------------


@attrs.define(frozen=True)
class ShaVectors:
    """A class to load SHA test vectors.

    Do not instantiate directly, use :meth:`load` instead.

    Args:
        hash_algorithm: The hash algorithm to use.
        orientation: The orientation of the implementation, either bit- or
            byte-oriented.
        short_msg_tests: Short message tests.
        long_msg_tests: Long message tests.
        montecarlo_tests: Monte-Carlo tests.

    Example:
        To load SHA-256 test vectors for a bit-oriented implementation.

        >>> from crypto_condor.vectors.SHA import Algorithm, Orientation, ShaVectors
        >>> vectors = ShaVectors.load(Algorithm.SHA_256, Orientation.BIT)
    """

    hash_algorithm: Algorithm
    orientation: Orientation
    short_msg: ShaNistVectors
    long_msg: ShaNistVectors
    montecarlo: ShaMonteCarloNistVectors

    @classmethod
    def load(
        cls,
        hash_algorithm: Algorithm,
        orientation: Orientation,
    ):
        """Loads SHA test vectors.

        Args:
            hash_algorithm: The hash algorithm to get vectors for.
            orientation: The orientation of the implementation, either bit- or
                byte-oriented.

        Returns:
            An instance of :class:`ShaVectors` with the corresponding test vectors.

        Raises:
            ShaVectorsError: If an error occurred while loading the vectors.
        """
        hash_name = _SHA_HASH_NAMES[str(hash_algorithm)]

        rsc = resources.files("crypto_condor")
        vectors_dir = rsc / "vectors/_sha/dat"

        # Load short message vectors.
        vector_file = vectors_dir / f"{hash_name}_{str(orientation)}_short.dat"
        short = ShaNistVectors()
        try:
            short.ParseFromString(vector_file.read_bytes())
        except message.DecodeError as error:
            logger.exception("Error decoding short message vectors")
            raise ShaVectorsError("Could not load SHA vectors") from error

        # Load long message vectors.
        vector_file = vectors_dir / f"{hash_name}_{str(orientation)}_long.dat"
        long = ShaNistVectors()
        try:
            long.ParseFromString(vector_file.read_bytes())
        except message.DecodeError as error:
            logger.exception("Error decoding long message vectors")
            raise ShaVectorsError("Could not load SHA vectors") from error

        # Load Monte-Carlo vectors.
        vector_file = vectors_dir / f"{hash_name}_{str(orientation)}_monte_carlo.dat"
        mc = ShaMonteCarloNistVectors()
        try:
            mc.ParseFromString(vector_file.read_bytes())
        except message.DecodeError as error:
            logger.exception("Error decoding test vectors")
            raise ShaVectorsError("Could not load SHA vectors") from error

        return cls(hash_algorithm, orientation, short, long, mc)
