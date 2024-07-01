"""Test vectors for SHAKE."""

import logging
from importlib import resources

import attrs
import strenum
from google.protobuf import message

from crypto_condor.vectors._sha.sha_pb2 import (
    ShakeMonteNistVectors,
    ShakeNistVectors,
    ShakeVariableNistVectors,
)

logger = logging.getLogger(__name__)

# --------------------------- Enums ---------------------------------------------------


class Algorithm(strenum.StrEnum):
    """Supported extensible output functions."""

    SHAKE128 = "SHAKE128"
    SHAKE256 = "SHAKE256"


class Orientation(strenum.StrEnum):
    """Orientation of the implementation."""

    BIT = "bit"
    BYTE = "byte"


_SHA_XOF_NAMES = {
    "SHAKE128": "shake128",
    "SHAKE256": "shake256",
}
"""Mapping of XOF algorithm names to test vector files.

Likely to change, for a list of supported functions see :enum:`Algorithm`.
"""

# --------------------------- Exceptions ----------------------------------------------


class ShakeVectorsError(Exception):
    """Exception for errors when loading vectors."""

    pass


# --------------------------- Vectors -------------------------------------------------


@attrs.define(frozen=True)
class ShakeVectors:
    """A class to load SHAKE test vectors.

    Do not instantiate directly, use :meth:`load` instead.

    Args:
        xof_algorithm: The XOF algorithm to use.
        orientation: The orientation of the implementation, either bit- or
            byte-oriented.
        short_msg_tests: Short message tests.
        long_msg_tests: Long message tests.
        montecarlo_tests: Monte-Carlo tests.

    Example:
        To load SHAKE128 test vectors for a bit-oriented implementation.

        >>> from crypto_condor.vectors.SHAKE import Algorithm, Orientation, ShakeVectors
        >>> vectors = ShakeVectors.load(Algorithm.SHAKE128, Orientation.BIT)
    """  # noqa: E501

    xof_algorithm: Algorithm
    orientation: Orientation
    short_msg: ShakeNistVectors
    long_msg: ShakeNistVectors
    montecarlo: ShakeMonteNistVectors
    variable: ShakeVariableNistVectors

    @classmethod
    def load(cls, xof_algorithm: Algorithm, orientation: Orientation):
        """Loads SHAKE test vectors.

        Args:
            xof_algorithm: The XOF algorithm to get vectors for.
            orientation: The orientation of the implementation, either bit- or
                byte-oriented.

        Returns:
            An instance of :class:`ShakeVectors` with the corresponding test vectors.

        Raises:
            ShaVectorsError: If an error occurred while loading the vectors.
        """
        xof_name = _SHA_XOF_NAMES[str(xof_algorithm)]

        rsc = resources.files("crypto_condor")
        vectors_dir = rsc / "vectors/_sha/dat"

        # Load short message vectors.
        vector_file = vectors_dir / f"{xof_name}_{str(orientation)}_short.dat"
        short = ShakeNistVectors()
        try:
            short.ParseFromString(vector_file.read_bytes())
        except message.DecodeError as error:
            logger.exception("Error decoding short message vectors")
            raise ShakeVectorsError("Could not load SHAKE vectors") from error

        # Load long message vectors.
        vector_file = vectors_dir / f"{xof_name}_{str(orientation)}_long.dat"
        long = ShakeNistVectors()
        try:
            long.ParseFromString(vector_file.read_bytes())
        except message.DecodeError as error:
            logger.exception("Error decoding long message vectors")
            raise ShakeVectorsError("Could not load SHAKE vectors") from error

        # Load Monte-Carlo vectors.
        vector_file = vectors_dir / f"{xof_name}_{str(orientation)}_monte.dat"
        mc = ShakeMonteNistVectors()
        try:
            mc.ParseFromString(vector_file.read_bytes())
        except message.DecodeError as error:
            logger.exception("Error decoding test vectors")
            raise ShakeVectorsError("Could not load SHAKE vectors") from error

        # Load variable length vectors.
        vector_file = vectors_dir / f"{xof_name}_{str(orientation)}_variable.dat"
        var = ShakeVariableNistVectors()
        try:
            var.ParseFromString(vector_file.read_bytes())
        except message.DecodeError as error:
            logger.exception("Error decoding test vectors")
            raise ShakeVectorsError("Could not load SHAKE vectors") from error

        return cls(xof_algorithm, orientation, short, long, mc, var)
