"""Test vectors for CRYSTALS-Kyber."""

import logging
from importlib import resources

import attrs
import strenum
from google.protobuf import message

from crypto_condor.vectors._kyber.kyber_pb2 import KyberNistTest, KyberNistVectors

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
            case "Kyber512" | "Kyber512-90s":
                member._sk_size_ = 1632
                member._pk_size_ = 800
                member._ct_size_ = 768
            case "Kyber768" | "Kyber768-90s":
                member._sk_size_ = 2400
                member._pk_size_ = 1184
                member._ct_size_ = 1088
            case "Kyber1024" | "Kyber1024-90s":
                member._sk_size_ = 3168
                member._pk_size_ = 1568
                member._ct_size_ = 1568
        return member

    @property
    def sk_size(self):
        """The secret key size of the parameter set in bytes."""
        return self._sk_size_

    @property
    def pk_size(self):
        """The public key size of the parameter set in bytes."""
        return self._pk_size_

    @property
    def ct_size(self):
        """The ciphertext size of the parameter set in bytes."""
        return self._ct_size_

    KYBER512 = "Kyber512"
    KYBER512_90s = "Kyber512-90s"
    KYBER768 = "Kyber768"
    KYBER768_90s = "Kyber768-90s"
    KYBER1024 = "Kyber1024"
    KYBER1024_90s = "Kyber1024-90s"


# --------------------------- Exceptions ----------------------------------------------


class KyberVectorsError(Exception):
    """Exception for errors when loading vectors."""

    pass


@attrs.define(frozen=True)
class KyberVectors:
    """A class to load Kyber test vectors.

    Do not instantiate directly, use :meth:`load` instead.

    Args:
        parameter_set: The parameter set of the vectors.
        tests: A list of the test vectors for the given parameter set.

    Example:
        Using :meth:`load` to load the test vectors:

        >>> from crypto_condor.vectors.Kyber import KyberVectors, Paramset
        >>> vectors = KyberVectors.load(Paramset.KYBER512)
    """

    parameter_set: Paramset
    tests: list[KyberNistTest]

    @classmethod
    def load(cls, parameter_set: Paramset):
        """Loads Kyber test vectors.

        Args:
            parameter_set: The parameter set of the vectors to load.

        Returns:
            An instance of :class:`KyberVectors` with the corresponding test vectors.

        Raises:
            FileNotFoundError: If the test vectors file was not found. This should not
                occur, as the vectors are bundled in the package.
            KyberVectorsError: If an error occurred while importing the file.
        """
        vectors_dir = resources.files("crypto_condor") / "vectors/_kyber/dat"
        filename = f"{str(parameter_set)}.dat"
        vector_file = vectors_dir / filename
        if not vector_file.is_file():
            raise FileNotFoundError("Missing vectors file %s" % filename)
        vectors = KyberNistVectors()
        try:
            vectors.ParseFromString(vector_file.read_bytes())
        except message.DecodeError as error:
            logger.debug(
                "Could not decode protobuf %s", str(vector_file), exc_info=True
            )
            raise KyberVectorsError("Could not load Kyber vectors") from error
        return cls(parameter_set, list(vectors.tests))
