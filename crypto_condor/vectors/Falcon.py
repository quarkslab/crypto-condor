"""Test vectors for Falcon."""

import logging
from importlib import resources

import attrs
import strenum
from google.protobuf import message

from crypto_condor.vectors._falcon.falcon_pb2 import (
    FalconNistKatTest,
    FalconNistKatVectors,
)

# --------------------------- Module --------------------------------------------------

logger = logging.getLogger(__name__)

# --------------------------- Enums ---------------------------------------------------


class Paramset(strenum.StrEnum):
    """Available parameter sets."""

    FALCON512 = "falcon512"
    FALCON1024 = "falcon1024"


# --------------------------- Exceptions ----------------------------------------------


class FalconVectorsError(Exception):
    """Exception for errors when loading vectors."""

    pass


# --------------------------- Vectors -------------------------------------------------


@attrs.define(frozen=True)
class FalconVectors:
    """A class to load Falcon test vectors.

    Do not instantiate directly, use :meth:`load` instead.

    Args:
        parameter_set:
            The parameter set of the vectors.
        tests:
            A list of the test vectors for the given parameter set.

    Example:
        Using :meth:`load` to load the test vectors:

        >>> from crypto_condor.vectors.Falcon import FalconVectors, Paramset
        >>> vectors = FalconVectors.load(Paramset.FALCON512)
    """

    parameter_set: Paramset
    tests: list[FalconNistKatTest]

    @classmethod
    def load(cls, parameter_set: Paramset):
        """Loads Falcon test vectors.

        Args:
            parameter_set:
                The parameter set of the vectors to load.

        Returns:
            An instance of :class:`FalconVectors` with the corresponding test vectors.

        Raises:
            FileNotFoundError:
                If the test vectors file was not found. This should not occur, as the
                vectors are bundled in the package.
            FalconVectorsError:
                If an error occurred while importing the file.
        """
        vectors_dir = resources.files("crypto_condor") / "vectors/_falcon/dat"
        filename = f"{str(parameter_set)}.dat"
        vector_file = vectors_dir / filename
        if not vector_file.is_file():
            raise FileNotFoundError("Missing vectors file %s" % filename)
        vectors = FalconNistKatVectors()
        try:
            vectors.ParseFromString(vector_file.read_bytes())
        except message.DecodeError as error:
            logger.debug(
                "Could not decode protobuf %s", str(vector_file), exc_info=True
            )
            raise FalconVectorsError("Could not load Falcon vectors") from error

        return cls(parameter_set, list(vectors.tests))
