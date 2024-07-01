"""Test vectors for SPHINCS+."""

import enum
import logging
from importlib import resources

import attrs
import strenum
from google.protobuf import message

from crypto_condor.vectors._sphincs.sphincs_pb2 import (
    SphincsNistKatTest,
    SphincsNistKatVectors,
)

# --------------------------- Module --------------------------------------------------

logger = logging.getLogger(__name__)

# --------------------------- Enums ---------------------------------------------------


# SPHINCS_HASHES = ["haraka", "sha256", "shake256"]
# SPHINCS_SIZES = ["128f", "128s", "192f", "192s", "256f", "256s"]
# SPHINCS_TYPES = ["robust", "simple"]
# SPHINCS_PARAMETER_SETS = [
#    f"sphincs-{h}-{s}-{t}"
#    for h in SPHINCS_HASHES
#    for s in SPHINCS_SIZES
#    for t in SPHINCS_TYPES
# ]


class Paramset(strenum.StrEnum):
    """Available parameter sets."""

    haraka_128f_robust = enum.auto()
    haraka_128f_simple = enum.auto()
    haraka_128s_robust = enum.auto()
    haraka_128s_simple = enum.auto()
    haraka_192f_robust = enum.auto()
    haraka_192f_simple = enum.auto()
    haraka_192s_robust = enum.auto()
    haraka_192s_simple = enum.auto()
    haraka_256f_robust = enum.auto()
    haraka_256f_simple = enum.auto()
    haraka_256s_robust = enum.auto()
    haraka_256s_simple = enum.auto()
    sha256_128f_robust = enum.auto()
    sha256_128f_simple = enum.auto()
    sha256_128s_robust = enum.auto()
    sha256_128s_simple = enum.auto()
    sha256_192f_robust = enum.auto()
    sha256_192f_simple = enum.auto()
    sha256_192s_robust = enum.auto()
    sha256_192s_simple = enum.auto()
    sha256_256f_robust = enum.auto()
    sha256_256f_simple = enum.auto()
    sha256_256s_robust = enum.auto()
    sha256_256s_simple = enum.auto()
    shake256_128f_robust = enum.auto()
    shake256_128f_simple = enum.auto()
    shake256_128s_robust = enum.auto()
    shake256_128s_simple = enum.auto()
    shake256_192f_robust = enum.auto()
    shake256_192f_simple = enum.auto()
    shake256_192s_robust = enum.auto()
    shake256_192s_simple = enum.auto()
    shake256_256f_robust = enum.auto()
    shake256_256f_simple = enum.auto()
    shake256_256s_robust = enum.auto()
    shake256_256s_simple = enum.auto()


# --------------------------- Exceptions ----------------------------------------------


class SphincsVectorsError(Exception):
    """Exception for errors when loading vectors."""

    pass


# --------------------------- Vectors -------------------------------------------------


@attrs.define(frozen=True)
class SphincsVectors:
    """A class to load SPHINCS+ test vectors.

    Do not instantiate directly, use :meth:`load` instead.

    Args:
        parameter_set:
            The parameter set of the vectors.
        tests:
            A list of the test vectors for the given parameter set.

    Example:
        Using :meth:`load` to load the test vectors:

        >>> from crypto_condor.vectors.SPHINCS import SphincsVectors, Paramset
        >>> vectors = SphincsVectors.load(Paramset.sha256_128f_robust)
    """

    parameter_set: Paramset
    tests: list[SphincsNistKatTest]

    @classmethod
    def load(cls, parameter_set: Paramset):
        """Loads SPHINCS+ test vectors.

        Args:
            parameter_set:
                The parameter set of the vectors to load.

        Returns:
            An instance of :class:`SphincsVectors` with the corresponding test vectors.

        Raises:
            FileNotFoundError:
                If the test vectors file was not found. This should not occur, as the
                vectors are bundled in the package.
            SphincsVectorsError:
                If an error occurred while importing the file.
        """
        vectors_dir = resources.files("crypto_condor") / "vectors/_sphincs/dat"
        filename = f"{str(parameter_set)}.dat"
        vector_file = vectors_dir / filename
        if not vector_file.is_file():
            raise FileNotFoundError("Missing vectors file %s" % filename)
        vectors = SphincsNistKatVectors()
        try:
            vectors.ParseFromString(vector_file.read_bytes())
        except message.DecodeError as error:
            logger.debug(
                "Could not decode protobuf %s", str(vector_file), exc_info=True
            )
            raise SphincsVectorsError("Could not load SPHINCS+ vectors") from error
        return cls(parameter_set, list(vectors.tests))
