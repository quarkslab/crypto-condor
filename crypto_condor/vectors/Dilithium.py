"""Test vectors for CRYSTALS-Dilithium."""

import logging
from importlib import resources

import attrs
import strenum
from google.protobuf import message

from crypto_condor.vectors._dilithium.dilithium_pb2 import (
    DilithiumNistTest,
    DilithiumNistVectors,
)

# --------------------------- Module --------------------------------------------------

logger = logging.getLogger(__name__)

# --------------------------- Enums ---------------------------------------------------


class Paramset(strenum.StrEnum):
    """Available parameter sets."""

    def __new__(cls, value):
        """Override __new__ to add custom properties."""
        member = str.__new__(cls, value)
        member._value_ = value
        match value:
            case "Dilithium2":
                member._pk_size_ = 1312
                member._sk_size_ = 2528
                member._sig_size_ = 2420
            case "Dilithium3":
                member._pk_size_ = 1952
                member._sk_size_ = 4000
                member._sig_size_ = 3293
            case "Dilithium5":
                member._pk_size_ = 2592
                member._sk_size_ = 4864
                member._sig_size_ = 4595
        return member

    @property
    def pk_size(self):
        """The size of the public key."""
        return self._pk_size_

    @property
    def sk_size(self):
        """The size of the secret key."""
        return self._sk_size_

    @property
    def sig_size(self):
        """The size of the signature."""
        return self._sig_size_

    DILITHIUM2 = "Dilithium2"
    DILITHIUM3 = "Dilithium3"
    DILITHIUM5 = "Dilithium5"


# --------------------------- Exceptions ----------------------------------------------


class DilithiumVectorsError(Exception):
    """Exception for errors when loading vectors."""

    pass


# --------------------------- Vectors -------------------------------------------------


@attrs.define(frozen=True)
class DilithiumVectors:
    """A class to load Dilithium test vectors.

    Do not instantiate directly, use :meth:`load` instead.

    Args:
        parameter_set:
            The parameter set of the vectors.
        tests:
            A list of the test vectors for the given parameter set.

    Example:
        Using :meth:`load` to load the test vectors:

        >>> from crypto_condor.vectors.Dilithium import DilithiumVectors, Paramset
        >>> vectors = DilithiumVectors.load(Paramset.DILITHIUM2)
    """

    parameter_set: Paramset
    tests: list[DilithiumNistTest]

    @classmethod
    def load(cls, parameter_set: Paramset):
        """Loads Dilithium test vectors.

        Args:
            parameter_set: The parameter set of the vectors to load.

        Returns:
            An instance of :class:`DilithiumVectors` with the corresponding test
            vectors.

        Raises:
            FileNotFoundError: If the test vectors file was not found. This should not
                occur, as the vectors are bundled in the package.
            DilithiumVectorsError: If an error occurred while importing the file.
        """
        vectors_dir = resources.files("crypto_condor") / "vectors/_dilithium/dat"
        filename = f"{str(parameter_set)}.dat"
        vector_file = vectors_dir / filename
        if not vector_file.is_file():
            raise FileNotFoundError("Missing vectors file %s" % filename)
        vectors = DilithiumNistVectors()
        try:
            vectors.ParseFromString(vector_file.read_bytes())
        except message.DecodeError as error:
            logger.debug(
                "Could not decode protobuf from %s", str(vector_file), exc_info=True
            )
            raise DilithiumVectorsError("Could not load Dilithium vectors") from error

        return cls(parameter_set, list(vectors.tests))
