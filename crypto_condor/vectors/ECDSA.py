"""Test vectors for ECDSA."""

import json
import logging
from importlib import resources
from typing import Literal, TypedDict, overload

import attrs
import strenum
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from google.protobuf import message

from crypto_condor.vectors._ecdsa.ecdsa_pb2 import (
    EcdsaNistSigGenVectors,
    EcdsaNistSigVerVectors,
)

logger = logging.getLogger(__name__)


# --------------------------- Enums ---------------------------------------------------


class Curve(strenum.StrEnum):
    """Defines all supported curves."""

    SECP192R1 = "secp192r1"
    SECP224R1 = "secp224r1"
    SECP256R1 = "secp256r1"
    SECP384R1 = "secp384r1"
    SECP521R1 = "secp521r1"
    SECP256K1 = "secp256k1"
    BRAINPOOLP224R1 = "brainpoolP224r1"
    BRAINPOOLP256R1 = "brainpoolP256r1"
    SECT283R1 = "sect283r1"
    SECT409R1 = "sect409r1"
    SECT571R1 = "sect571r1"

    @classmethod
    def from_name(cls, name: str):
        """Matches a curve name to its corresponding enum.

        Args:
            name: The name of the curve.

        Returns:
            The corresponding :class:`EcdsaCurve`.

        Raises:
            ValueError: If the curve is not supported or the name not recognized.
        """
        match name.casefold():
            case (
                "p192"
                | "nist p-192"
                | "p-192"
                | "prime192v1"
                | "secp192r1"
                | "nistp192"
            ):
                return cls.SECP192R1
            case (
                "p224"
                | "nist p-224"
                | "p-224"
                | "prime224v1"
                | "secp224r1"
                | "nistp224"
            ):
                return cls.SECP224R1
            case (
                "p256"
                | "nist p-256"
                | "p-256"
                | "prime256v1"
                | "secp256r1"
                | "nistp256"
            ):
                return cls.SECP256R1
            case (
                "p384"
                | "nist p-384"
                | "p-384"
                | "prime384v1"
                | "secp384r1"
                | "nistp384"
            ):
                return cls.SECP384R1
            case (
                "p521"
                | "nist p-521"
                | "p-521"
                | "prime521v1"
                | "secp521r1"
                | "nistp521"
            ):
                return cls.SECP521R1
            case "secp256k1":
                return cls.SECP256K1
            case "brainpoolp224r1":
                return cls.BRAINPOOLP224R1
            case "brainpoolp256r1":
                return cls.BRAINPOOLP256R1
            case "b283" | "b-283" | "sect283r1":
                return cls.SECT283R1
            case "b409" | "b-409" | "sect409r1":
                return cls.SECT409R1
            case "b571" | "b-571" | "sect571r1":
                return cls.SECT571R1
            case _:
                raise ValueError("Unsupported curve %s" % name)

    def get_nist_name(self) -> str | None:
        """Returns the curve name used in NIST test vectors.

        None is returned if there are no NIST vectors that use this curve.
        """
        match self:
            case Curve.SECP192R1:
                return "P-192"
            case Curve.SECP224R1:
                return "P-224"
            case Curve.SECP256R1:
                return "P-256"
            case Curve.SECP384R1:
                return "P-384"
            case Curve.SECP521R1:
                return "P-521"
            case Curve.SECT283R1:
                return "B-283"
            case Curve.SECT409R1:
                return "B-409"
            case Curve.SECT571R1:
                return "B-571"
            case Curve.SECP256K1 | Curve.BRAINPOOLP224R1 | Curve.BRAINPOOLP256R1:
                # No NIST test vectors.
                return None

    def get_wycheproof_name(self) -> str | None:
        """Returns the curve name used in Wycheproof test vectors.

        None is returned if there are no Wycheproof vectors that use this curve.
        """
        # Wycheproof uses the same names as the enum except for sect* curves
        # which are not supported.
        match self:
            case Curve.SECT283R1 | Curve.SECT409R1 | Curve.SECT571R1:
                return None
            case _:
                return str(self)

    def get_curve_instance(self):
        """Returns an instance of the corresponding curve.

        Curves come from the :mod:`cryptography.hazmat.primitives.asymmetric.ec` module.
        """
        match self:
            case Curve.SECP192R1:
                return ec.SECP192R1()
            case Curve.SECP224R1:
                return ec.SECP224R1()
            case Curve.SECP256R1:
                return ec.SECP256R1()
            case Curve.SECP384R1:
                return ec.SECP384R1()
            case Curve.SECP521R1:
                return ec.SECP521R1()
            case Curve.SECP256K1:
                return ec.SECP256K1()
            case Curve.BRAINPOOLP256R1:
                return ec.BrainpoolP256R1()
            case Curve.SECT283R1:
                return ec.SECT283R1()
            case Curve.SECT409R1:
                return ec.SECT409R1()
            case Curve.SECT571R1:
                return ec.SECT571R1()
            case Curve.BRAINPOOLP224R1:
                # No Wycheproof test vectors.
                return None


class Hash(strenum.StrEnum):
    """Defines all supported hash functions."""

    SHA_256 = "SHA-256"
    SHA_384 = "SHA-384"
    SHA_512 = "SHA-512"
    SHA3_256 = "SHA3-256"
    SHA3_384 = "SHA3-384"
    SHA3_512 = "SHA3-512"

    @classmethod
    def from_name(cls, name: str):
        """Matches a hash function name to its corresponding enum.

        Args:
            name: The name of the hash function.

        Returns:
            The corresponding :class:`EcdsaHash`.

        Raises:
            ValueError: If the hash function is not supported or the name not
                recognized.
        """
        # Trying to be clever by casefolding *and* removing the dash.
        match name.casefold().replace("-", ""):
            case "sha256":
                return cls.SHA_256
            case "sha384":
                return cls.SHA_384
            case "sha512":
                return cls.SHA_512
            case "sha3256":
                return cls.SHA3_256
            case "sha3384":
                return cls.SHA3_384
            case "sha3512":
                return cls.SHA3_512
            case _:
                raise ValueError("Unsupported hash function %s" % name)

    def get_nist_name(self):
        """Returns the hash function name used in NIST test vectors.

        None is returned if there are no NIST vectors that use this hash function.
        """
        match self:
            case Hash.SHA_256 | Hash.SHA_384 | Hash.SHA_512:
                return str(self)
            case _:
                return None

    def get_wycheproof_name(self):
        """Returns the hash function name used in Wycheproof test vectors.

        None is returned if there are no Wycheproof vectors that use this hash function.
        """
        match self:
            case Hash.SHA_256 | Hash.SHA_384 | Hash.SHA_512:
                return str(self).lower().replace("-", "")
            case _:
                return str(self).lower().replace("-", "_")

    def get_hash_instance(self):
        """Returns an instance of the corresponding hash function.

        Hash functions come from :mod:`cryptography.hazmat.primitives.hashes` module.
        """
        match self:
            case Hash.SHA_256:
                return hashes.SHA256()
            case Hash.SHA_384:
                return hashes.SHA384()
            case Hash.SHA_512:
                return hashes.SHA512()
            case Hash.SHA3_256:
                return hashes.SHA3_256()
            case Hash.SHA3_384:
                return hashes.SHA3_384()
            case Hash.SHA3_512:
                return hashes.SHA3_512()


class EcdsaVectorType(strenum.StrEnum):
    """Defines the different types of test vectors available."""

    # Names are in lowercase since the vectors filenames are lowercase.
    SIGVER = "sigver"
    """Vectors to test a function that verifies signatures."""
    SIGGEN = "siggen"
    """Vectors to test a function that generates signatures."""


# --------------------------- Exceptions ----------------------------------------------


class EcdsaVectorsError(Exception):
    """Exception for errors when loading or parsing vectors."""

    pass


class EcdsaParametersError(Exception):
    """Exception for parameter errors."""

    pass


# --------------------------- Dataclasses ---------------------------------------------


@overload
def _load_nist_vectors(
    vectors_type: Literal[EcdsaVectorType.SIGGEN],
    curve: Curve,
    hash_function: Hash,
) -> EcdsaNistSigGenVectors: ...


@overload
def _load_nist_vectors(
    vectors_type: Literal[EcdsaVectorType.SIGVER],
    curve: Curve,
    hash_function: Hash,
) -> EcdsaNistSigVerVectors: ...


def _load_nist_vectors(
    vectors_type: EcdsaVectorType, curve: Curve, hash_function: Hash
) -> EcdsaNistSigGenVectors | EcdsaNistSigVerVectors:
    """Loads NIST ECDSA SigVer test vectors.

    Args:
        vectors_type: The type of vectors to load, either SIGGEN or SIGVER.
        curve: The elliptic curve.
        hash_function: The hash function used.

    Returns:
        The corresponding ECDSA vectors.

    Raises:
        EcdsaParametersError: If the curve, hash function, or the combination of both
            doesn't have corresponding NIST vectors.
        EcdsaVectorsError: If an error occurred while loading the vectors.
    """
    if curve.get_nist_name() is None:
        raise EcdsaParametersError(
            "There are no NIST vectors for the %s curve" % str(curve)
        )
    if hash_function.get_nist_name() is None:
        raise EcdsaParametersError(
            "There are no NIST vectors for the %s hash function" % str(hash_function)
        )

    vectors_dir = resources.files("crypto_condor").joinpath("vectors/_ecdsa/dat")
    filename = f"ecdsa_{str(vectors_type)}_{curve.get_nist_name()}_{hash_function.get_nist_name()}.dat"  # noqa: E501
    vectors_file = vectors_dir / filename
    if not vectors_file.is_file():
        raise EcdsaParametersError(
            "There are no NIST vectors for (%s, %s)" % (str(curve), str(hash_function))
        )

    vectors: EcdsaNistSigGenVectors | EcdsaNistSigVerVectors
    if vectors_type == EcdsaVectorType.SIGGEN:
        vectors = EcdsaNistSigGenVectors()
    else:
        vectors = EcdsaNistSigVerVectors()

    try:
        vectors.ParseFromString(vectors_file.read_bytes())
    except message.DecodeError as error:
        logger.debug(error, exc_info=True)
        raise EcdsaVectorsError("Could not load NIST (compliance) vectors") from error
    return vectors


class EcdsaWycheproofTest(TypedDict):
    """Represents a single Wycheproof ECDSA test."""

    tcId: int
    comment: str
    msg: str
    sig: str
    result: str
    flags: list[str]


class EcdsaWycheproofKey(TypedDict):
    """Represents a Wycheproof ECDSA key.

    ECDSA test groups share a key which is provided in different formats. This format
    contains the curve used and the coordinates.
    """

    curve: str
    keySize: int
    type: str
    uncompressed: str
    wx: str
    wy: str


class EcdsaWycheproofGroup(TypedDict):
    """Represents a Wycheproof ECDSA test group."""

    key: EcdsaWycheproofKey
    keyDer: str
    keyPem: str
    sha: str
    type: str
    tests: list[EcdsaWycheproofTest]


class EcdsaWycheproofVectors(TypedDict):
    """Represents a Wycheproof file of ECDSA test vectors.

    Note that some fields are missing as they are not used by crypto-condor.
    """

    algorithm: str
    numberOfTests: int
    header: list[str]
    notes: dict[str, str]
    testGroups: list[EcdsaWycheproofGroup]


def _load_wycheproof_vectors(
    curve: Curve, hash_function: Hash
) -> EcdsaWycheproofVectors:
    """Loads Wycheproof test vectors.

    Args:
        curve: The curve to get test vectors for.
        hash_function: The hash function to get test vectors for.

    Returns:
        The corresponding test vectors.

    Raises:
        EcdsaParametersError: If the curve, hash function, or the combination of both
            doesn't have corresponding test vectors.
        EcdsaVectorsError: If an error occurred while loading the vectors.
    """
    curve_name = curve.get_wycheproof_name()
    hash_name = hash_function.get_wycheproof_name()
    if curve_name is None:
        raise EcdsaParametersError(
            "There are no Wycheproof vectors for the %s curve" % str(curve)
        )
    if hash_name is None:
        raise EcdsaParametersError(
            "There are no Wycheproof vectors for the %s hash function"
            % str(hash_function)
        )

    vectors_dir = resources.files("crypto_condor") / "vectors/_ecdsa/wycheproof"
    filename = f"ecdsa_{curve_name}_{hash_name}_test.json"
    vectors_file = vectors_dir / filename
    if not vectors_file.is_file():
        raise EcdsaParametersError(
            "There are no Wycheproof vectors for curve %s and hash function %s"
            % (str(curve), str(hash_function))
        )

    try:
        data = vectors_file.read_bytes()
        vectors = json.loads(data)
        return vectors
    except OSError as error:
        logger.debug(
            "Error reading Wycheproof file %s: %s", filename, error, exc_info=True
        )
        raise EcdsaVectorsError("Could not read Wycheproof test vectors") from error
    except json.JSONDecodeError as error:
        logger.debug(
            "Error decoding Wycheproof file %s: %s", filename, error, exc_info=True
        )
        raise EcdsaVectorsError("Could not decode Wycheproof test vectors") from error


@attrs.define
class EcdsaSigVerVectors:
    """A class to group ECDSA test vectors for signature verification.

    Do not instantiate directly, use :meth:`load` to load the corresponding test
    vectors.

    Args:
        parameters: The parameters to get test vectors for.
        nist_vectors: An instance of loaded NIST vectors if they exist for the given
            parameters, None otherwise.
        wycheproof_vectors: An instance of loaded Wycheproof vectors if they exist for
            the given parameters, None otherwise.
    """

    curve: Curve
    hash_function: Hash
    nist: EcdsaNistSigVerVectors | None
    wycheproof: EcdsaWycheproofVectors | None

    @classmethod
    def load(
        cls,
        curve: Curve,
        hash_function: Hash,
        *,
        compliance: bool = True,
        resilience: bool = True,
    ):
        """Loads ECDSA SigVer test vectors.

        Args:
            curve: The elliptic curve to get test vectors for.
            hash_function: The hash function to get test vectors for.

        Keyword Args:
            compliance: Whether to load compliance test vectors.
            resilience: Whether to load resilience test vectors.

        Returns:
            An :class:`EcdsaSigVerVectors` instance with the corresponding test vectors.
        """
        if compliance:
            try:
                nist_vectors = _load_nist_vectors(
                    EcdsaVectorType.SIGVER, curve, hash_function
                )
            except EcdsaParametersError as error:
                logger.warning(error)
                nist_vectors = None
        else:
            nist_vectors = None

        if resilience:
            try:
                wycheproof_vectors = _load_wycheproof_vectors(curve, hash_function)
            except EcdsaParametersError as error:
                logger.warning(error)
                wycheproof_vectors = None
        else:
            wycheproof_vectors = None

        return cls(curve, hash_function, nist_vectors, wycheproof_vectors)


@attrs.define
class EcdsaSigGenVectors:
    """ECDSA signature generation test vectors.

    Do not instantiate directly, use :meth:`load` to get test vectors for a given curve
    and hash function.

    Args:
        curve: The elliptic curve to use.
        hash_function: The hash function used to generate signatures.
        nist: The NIST test vectors for the given parameters, None if there are no test
            vectors for those parameters.
    """

    curve: Curve
    hash_function: Hash
    nist: EcdsaNistSigGenVectors | None

    @classmethod
    def load(
        cls,
        curve: Curve,
        hash_function: Hash,
    ):
        """Loads ECDSA SigGen test vectors.

        Args:
            curve: The elliptic curve to get test vectors for.
            hash_function: The hash function to get test vectors for.

        Returns:
            An :class:`EcdsaSigGenVectors` instance with the corresponding test vectors.
        """
        try:
            vectors = _load_nist_vectors(EcdsaVectorType.SIGGEN, curve, hash_function)
        except EcdsaParametersError as error:
            logger.warning(error)
            return cls(curve, hash_function, None)

        return cls(curve, hash_function, vectors)
