"""Test vectors for RSASSA."""

import json
import logging
from importlib import resources
from typing import TypedDict

import attrs
import strenum

from crypto_condor.vectors._rsa.rsa_pb2 import (
    RsaNistSigGenVectors,
    RsaNistSigVerVectors,
)

# --------------------------- Module --------------------------------------------------

logger = logging.getLogger(__name__)


# --------------------------- Enums ---------------------------------------------------


class Scheme(strenum.StrEnum):
    """RSA signature schemes."""

    PKCS = "RSASSA-PKCS1-v1_5"
    PSS = "RSASSA-PSS"


class Hash(strenum.StrEnum):
    """A list of available hash functions."""

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


# --------------------------- Vector files --------------------------------------------
_NIST_SIGGEN_PKCS_FILES = {
    "SHA-224": [
        "rsa_signature_2048_sha224.dat",
        "rsa_signature_3072_sha224.dat",
    ],
    "SHA-256": [
        "rsa_signature_2048_sha256.dat",
        "rsa_signature_3072_sha256.dat",
    ],
    "SHA-384": [
        "rsa_signature_2048_sha384.dat",
        "rsa_signature_3072_sha384.dat",
    ],
    "SHA-512": [
        "rsa_signature_2048_sha512.dat",
        "rsa_signature_3072_sha512.dat",
    ],
    "SHA-512/224": [
        "rsa_signature_2048_sha512_224.dat",
        "rsa_signature_3072_sha512_224.dat",
    ],
    "SHA-512/256": [
        "rsa_signature_2048_sha512_256.dat",
        "rsa_signature_3072_sha512_256.dat",
    ],
}
"""Files of NIST RSASSA-PKCS1-v1_5 vectors, indexed by hash algorithm."""

_NIST_SIGGEN_PSS_FILES = {
    "SHA-224": [
        "rsa_pss_2048_sha224.dat",
        "rsa_pss_3072_sha224.dat",
    ],
    "SHA-256": [
        "rsa_pss_2048_sha256.dat",
        "rsa_pss_3072_sha256.dat",
    ],
    "SHA-384": [
        "rsa_pss_2048_sha384.dat",
        "rsa_pss_3072_sha384.dat",
    ],
    "SHA-512": [
        "rsa_pss_2048_sha512.dat",
        "rsa_pss_3072_sha512.dat",
    ],
    "SHA-512/224": [
        "rsa_pss_2048_sha512_224.dat",
        "rsa_pss_3072_sha512_224.dat",
    ],
    "SHA-512/256": [
        "rsa_pss_2048_sha512_256.dat",
        "rsa_pss_3072_sha512_256.dat",
    ],
}
"""Files of NIST RSASSA-PSS vectors, indexed by hash algorithm."""

_NIST_SIGVER_PKCS_FILES = {
    "SHA-1": [
        "rsa_ver_signature_1024_sha1_1.dat",
        "rsa_ver_signature_1024_sha1_2.dat",
        "rsa_ver_signature_1024_sha1_3.dat",
        "rsa_ver_signature_2048_sha1_1.dat",
        "rsa_ver_signature_2048_sha1_2.dat",
        "rsa_ver_signature_2048_sha1_3.dat",
        "rsa_ver_signature_3072_sha1_1.dat",
        "rsa_ver_signature_3072_sha1_2.dat",
        "rsa_ver_signature_3072_sha1_3.dat",
    ],
    "SHA-224": [
        "rsa_ver_signature_1024_sha224_1.dat",
        "rsa_ver_signature_1024_sha224_2.dat",
        "rsa_ver_signature_1024_sha224_3.dat",
        "rsa_ver_signature_2048_sha224_1.dat",
        "rsa_ver_signature_2048_sha224_2.dat",
        "rsa_ver_signature_2048_sha224_3.dat",
        "rsa_ver_signature_3072_sha224_1.dat",
        "rsa_ver_signature_3072_sha224_2.dat",
        "rsa_ver_signature_3072_sha224_3.dat",
    ],
    "SHA-256": [
        "rsa_ver_signature_1024_sha256_1.dat",
        "rsa_ver_signature_1024_sha256_2.dat",
        "rsa_ver_signature_1024_sha256_3.dat",
        "rsa_ver_signature_2048_sha256_1.dat",
        "rsa_ver_signature_2048_sha256_2.dat",
        "rsa_ver_signature_2048_sha256_3.dat",
        "rsa_ver_signature_3072_sha256_1.dat",
        "rsa_ver_signature_3072_sha256_2.dat",
        "rsa_ver_signature_3072_sha256_3.dat",
    ],
    "SHA-384": [
        "rsa_ver_signature_1024_sha384_1.dat",
        "rsa_ver_signature_1024_sha384_2.dat",
        "rsa_ver_signature_1024_sha384_3.dat",
        "rsa_ver_signature_2048_sha384_1.dat",
        "rsa_ver_signature_2048_sha384_2.dat",
        "rsa_ver_signature_2048_sha384_3.dat",
        "rsa_ver_signature_3072_sha384_1.dat",
        "rsa_ver_signature_3072_sha384_2.dat",
        "rsa_ver_signature_3072_sha384_3.dat",
    ],
    "SHA-512": [
        "rsa_ver_signature_1024_sha512_1.dat",
        "rsa_ver_signature_1024_sha512_2.dat",
        "rsa_ver_signature_1024_sha512_3.dat",
        "rsa_ver_signature_2048_sha512_1.dat",
        "rsa_ver_signature_2048_sha512_2.dat",
        "rsa_ver_signature_2048_sha512_3.dat",
        "rsa_ver_signature_3072_sha512_1.dat",
        "rsa_ver_signature_3072_sha512_2.dat",
        "rsa_ver_signature_3072_sha512_3.dat",
    ],
    "SHA-512/224": [
        "rsa_ver_signature_1024_sha512_224_1.dat",
        "rsa_ver_signature_1024_sha512_224_2.dat",
        "rsa_ver_signature_1024_sha512_224_3.dat",
        "rsa_ver_signature_2048_sha512_224_1.dat",
        "rsa_ver_signature_2048_sha512_224_2.dat",
        "rsa_ver_signature_2048_sha512_224_3.dat",
        "rsa_ver_signature_3072_sha512_224_1.dat",
        "rsa_ver_signature_3072_sha512_224_2.dat",
        "rsa_ver_signature_3072_sha512_224_3.dat",
    ],
    "SHA-512/256": [
        "rsa_ver_signature_1024_sha512_256_1.dat",
        "rsa_ver_signature_1024_sha512_256_2.dat",
        "rsa_ver_signature_1024_sha512_256_3.dat",
        "rsa_ver_signature_2048_sha512_256_1.dat",
        "rsa_ver_signature_2048_sha512_256_2.dat",
        "rsa_ver_signature_2048_sha512_256_3.dat",
        "rsa_ver_signature_3072_sha512_256_1.dat",
        "rsa_ver_signature_3072_sha512_256_2.dat",
        "rsa_ver_signature_3072_sha512_256_3.dat",
    ],
}
"""Files of NIST RSASSA-PKCS1-v1_5 vectors, indexed by hash algorithm."""

_NIST_SIGVER_PSS_FILES = {
    "SHA-1": [
        "rsa_ver_pss_1024_sha1_1.dat",
        "rsa_ver_pss_1024_sha1_2.dat",
        "rsa_ver_pss_1024_sha1_3.dat",
        "rsa_ver_pss_2048_sha1_1.dat",
        "rsa_ver_pss_2048_sha1_2.dat",
        "rsa_ver_pss_2048_sha1_3.dat",
        "rsa_ver_pss_3072_sha1_1.dat",
        "rsa_ver_pss_3072_sha1_2.dat",
        "rsa_ver_pss_3072_sha1_3.dat",
    ],
    "SHA-224": [
        "rsa_ver_pss_1024_sha224_1.dat",
        "rsa_ver_pss_1024_sha224_2.dat",
        "rsa_ver_pss_1024_sha224_3.dat",
        "rsa_ver_pss_2048_sha224_1.dat",
        "rsa_ver_pss_2048_sha224_2.dat",
        "rsa_ver_pss_2048_sha224_3.dat",
        "rsa_ver_pss_3072_sha224_1.dat",
        "rsa_ver_pss_3072_sha224_2.dat",
        "rsa_ver_pss_3072_sha224_3.dat",
    ],
    "SHA-256": [
        "rsa_ver_pss_1024_sha256_1.dat",
        "rsa_ver_pss_1024_sha256_2.dat",
        "rsa_ver_pss_1024_sha256_3.dat",
        "rsa_ver_pss_2048_sha256_1.dat",
        "rsa_ver_pss_2048_sha256_2.dat",
        "rsa_ver_pss_2048_sha256_3.dat",
        "rsa_ver_pss_3072_sha256_1.dat",
        "rsa_ver_pss_3072_sha256_2.dat",
        "rsa_ver_pss_3072_sha256_3.dat",
    ],
    "SHA-384": [
        "rsa_ver_pss_1024_sha384_1.dat",
        "rsa_ver_pss_1024_sha384_2.dat",
        "rsa_ver_pss_1024_sha384_3.dat",
        "rsa_ver_pss_2048_sha384_1.dat",
        "rsa_ver_pss_2048_sha384_2.dat",
        "rsa_ver_pss_2048_sha384_3.dat",
        "rsa_ver_pss_3072_sha384_1.dat",
        "rsa_ver_pss_3072_sha384_2.dat",
        "rsa_ver_pss_3072_sha384_3.dat",
    ],
    "SHA-512": [
        "rsa_ver_pss_1024_sha512_1.dat",
        "rsa_ver_pss_1024_sha512_2.dat",
        "rsa_ver_pss_1024_sha512_3.dat",
        "rsa_ver_pss_2048_sha512_1.dat",
        "rsa_ver_pss_2048_sha512_2.dat",
        "rsa_ver_pss_2048_sha512_3.dat",
        "rsa_ver_pss_3072_sha512_1.dat",
        "rsa_ver_pss_3072_sha512_2.dat",
        "rsa_ver_pss_3072_sha512_3.dat",
    ],
    "SHA-512/224": [
        "rsa_ver_pss_1024_sha512_224_1.dat",
        "rsa_ver_pss_1024_sha512_224_2.dat",
        "rsa_ver_pss_1024_sha512_224_3.dat",
        "rsa_ver_pss_2048_sha512_224_1.dat",
        "rsa_ver_pss_2048_sha512_224_2.dat",
        "rsa_ver_pss_2048_sha512_224_3.dat",
        "rsa_ver_pss_3072_sha512_224_1.dat",
        "rsa_ver_pss_3072_sha512_224_2.dat",
        "rsa_ver_pss_3072_sha512_224_3.dat",
    ],
    "SHA-512/256": [
        "rsa_ver_pss_1024_sha512_256_1.dat",
        "rsa_ver_pss_1024_sha512_256_2.dat",
        "rsa_ver_pss_1024_sha512_256_3.dat",
        "rsa_ver_pss_2048_sha512_256_1.dat",
        "rsa_ver_pss_2048_sha512_256_2.dat",
        "rsa_ver_pss_2048_sha512_256_3.dat",
        "rsa_ver_pss_3072_sha512_256_1.dat",
        "rsa_ver_pss_3072_sha512_256_2.dat",
        "rsa_ver_pss_3072_sha512_256_3.dat",
    ],
}
"""Files of NIST RSASSA-PSS vectors, indexed by hash algorithm."""

_WYCHEPROOF_SIGVER_PKCS_FILES = {
    "SHA-224": [
        "rsa_signature_2048_sha224_test.json",
    ],
    "SHA-256": [
        "rsa_signature_2048_sha256_test.json",
        "rsa_signature_3072_sha256_test.json",
    ],
    "SHA-384": [
        "rsa_signature_2048_sha384_test.json",
        "rsa_signature_3072_sha384_test.json",
        "rsa_signature_4096_sha384_test.json",
    ],
    "SHA-512": [
        "rsa_signature_2048_sha512_test.json",
        "rsa_signature_3072_sha512_test.json",
        "rsa_signature_4096_sha512_test.json",
    ],
    "SHA-512/224": [
        "rsa_signature_2048_sha512_224_test.json",
    ],
    "SHA-512/256": [
        "rsa_signature_2048_sha512_256_test.json",
        "rsa_signature_3072_sha512_256_test.json",
        "rsa_signature_4096_sha512_256_test.json",
    ],
    "SHA3-224": [
        "rsa_signature_2048_sha3_224_test.json",
    ],
    "SHA3-256": [
        "rsa_signature_2048_sha3_256_test.json",
        "rsa_signature_3072_sha3_256_test.json",
    ],
    "SHA3-384": [
        "rsa_signature_2048_sha3_384_test.json",
        "rsa_signature_3072_sha3_384_test.json",
    ],
    "SHA3-512": [
        "rsa_signature_2048_sha3_512_test.json",
        "rsa_signature_3072_sha3_512_test.json",
    ],
}
"""Files of Wycheproof RSASSA-PKCS1-v1_5 vectors, indexed by hash algorithm."""

_WYCHEPROOF_SIGVER_PSS_FILES = {
    "SHA-1": [
        "rsa_pss_2048_sha1_mgf1_20_test.json",
    ],
    "SHA-256": [
        "rsa_pss_2048_sha256_mgf1_0_test.json",
        "rsa_pss_2048_sha256_mgf1_32_test.json",
        "rsa_pss_3072_sha256_mgf1_32_test.json",
        "rsa_pss_4096_sha256_mgf1_32_test.json",
    ],
    "SHA-512": [
        "rsa_pss_4096_sha512_mgf1_32_test.json",
    ],
    "SHA-512/256": [
        "rsa_pss_2048_sha512_256_mgf1_28_test.json",
        "rsa_pss_2048_sha512_256_mgf1_32_test.json",
    ],
}
"""Files of Wycheproof RSASSA-PSS vectors, indexed by hash algorithm."""


# --------------------------- Wycheproof ----------------------------------------------
class RsaWycheproofSigTest(TypedDict):
    """Represents a single Wycheproof signature test."""

    tcId: int
    comment: str
    msg: str
    sig: str
    result: str
    flags: list[str]


class RsaWycheproofSigGroup(TypedDict):
    """Represents a single Wycheproof signature group."""

    e: str
    keyAsn: str
    keyDer: str
    keyJwk: dict[str, str]
    keyPem: str
    keysize: int
    n: str
    sha: str
    tests: list[RsaWycheproofSigTest]


class RsaWycheproofSigVectors(TypedDict):
    """Represents a file of Wycheproof signature vectors."""

    algorithm: str
    numberOfTests: int
    header: list[str]
    notes: dict[str, str]
    testGroups: list[RsaWycheproofSigGroup]


# --------------------------- Loader functions ----------------------------------------
def load_nist_sigver_vectors(
    scheme: Scheme, hash_algorithm: Hash
) -> dict[str, RsaNistSigVerVectors] | None:
    """Loads NIST SigVer vectors.

    Args:
        scheme: The signature scheme to get vectors of.
        hash_algorithm: The hash algorithm used to generate the signatures.

    Returns:
        A dictionary with test vectors indexed by filename, or None if there aren't
        vectors for the given parameters.
    """
    if scheme == Scheme.PSS:
        files = _NIST_SIGVER_PSS_FILES.get(hash_algorithm, None)
    else:
        files = _NIST_SIGVER_PKCS_FILES.get(hash_algorithm, None)
    if files is None:
        return None
    vectors_dir = resources.files("crypto_condor") / "vectors/_rsa/dat"
    vectors = dict()
    for filename in files:
        file = vectors_dir / filename
        svv = RsaNistSigVerVectors()
        svv.ParseFromString(file.read_bytes())
        vectors[filename] = svv
    return vectors


def load_wycheproof_vectors(
    scheme: Scheme, hash_algorithm: Hash
) -> dict[str, RsaWycheproofSigVectors] | None:
    """Loads Wycheproof test vectors for signature verification.

    Args:
        scheme: The scheme of the test vectors to load.
        hash_algorithm: The hash algorithm used to generate the test vectors.

    Returns:
        A dictionary of test vectors, indexed by the names of the files loaded, or None
        if there aren't vectors for the given parameters.
    """
    rsc = resources.files("crypto_condor")
    vectors_dir = rsc / "vectors/_rsa/wycheproof"
    files: list[str] | None
    match scheme:
        case Scheme.PKCS:
            files = _WYCHEPROOF_SIGVER_PKCS_FILES.get(hash_algorithm, None)
        case Scheme.PSS:
            files = _WYCHEPROOF_SIGVER_PSS_FILES.get(hash_algorithm, None)
    if files is None:
        return None
    vectors = dict()
    for filename in files:
        file = vectors_dir / filename
        data = json.loads(file.read_text())
        vectors[filename] = data
    return vectors


# --------------------------- Vectors -------------------------------------------------
@attrs.define(frozen=True)
class RsaSigGenVectors:
    """RSA vectors for signature generation.

    Do not instantiate directly, use :meth:`load` instead.

    Args:
        scheme: The encryption scheme of the test vectors.
        hash_algorithm: The hash algorithm used to generate the vectors.
        nist: A dictionary of NIST vectors or None if there are no vectors for the given
            parameters.

    Example:
        Using :meth:`load` to load the test vectors:

        >>> from crypto_condor.vectors.RSASSA import Hash, RsaSigGenVectors, Scheme
        >>> scheme = Scheme.PSS
        >>> hash_algorithm = Hash.SHA_256
        >>> vectors = RsaSigGenVectors.load(scheme, hash_algorithm)
    """

    scheme: Scheme
    hash_algorithm: Hash
    nist: dict[str, RsaNistSigGenVectors] | None

    @classmethod
    def load(cls, scheme: Scheme, hash_algorithm: Hash):
        """Loads RSASSA signature generation test vectors.

        Args:
            scheme: The signature scheme to get vectors of.
            hash_algorithm: The hash algorithm used to generate the signatures.

        Returns:
            An instance of :class:`RsaSigGenVectors`.
        """
        if scheme == Scheme.PSS:
            files = _NIST_SIGGEN_PSS_FILES.get(hash_algorithm, None)
        else:
            files = _NIST_SIGGEN_PKCS_FILES.get(hash_algorithm, None)
        if files is None:
            return cls(scheme, hash_algorithm, None)
        vectors_dir = resources.files("crypto_condor") / "vectors/_rsa/dat"
        vectors = dict()
        for filename in files:
            file = vectors_dir / filename
            sgv = RsaNistSigGenVectors()
            sgv.ParseFromString(file.read_bytes())
            vectors[filename] = sgv
        return cls(scheme, hash_algorithm, vectors)


@attrs.define(frozen=True)
class RsaSigVerVectors:
    """RSA vectors for signature verification.

    Do not instantiate directly, use :meth:`load`.

    Args:
        scheme: The encryption scheme of the test vectors.
        hash_algorithm: The hash algorithm used to generate the vectors.
        nist: A dictionary of NIST vectors or None if there are no vectors for the given
            parameters.
        wycheproof: A dictionary of Wycheproof vectors or None if there are no vectors
            for the given parameters.

    Example:
        Using :meth:`load` to load the test vectors:

        >>> from crypto_condor.vectors.RSASSA import Hash, RsaSigVerVectors, Scheme
        >>> scheme = Scheme.PSS
        >>> hash_algorithm = Hash.SHA_256
        >>> vectors = RsaSigVerVectors.load(scheme, hash_algorithm)
    """

    scheme: Scheme
    hash_algorithm: Hash
    nist: dict[str, RsaNistSigVerVectors] | None
    wycheproof: dict[str, RsaWycheproofSigVectors] | None

    @classmethod
    def load(cls, scheme: Scheme, hash_algorithm: Hash):
        """Loads SigVer vectors.

        Args:
            scheme: The signature scheme to get vectors of.
            hash_algorithm: The hash algorithm used to generate the signatures.

        Returns:
            An instance of :class:`RsaSigVerVectors`.
        """
        nist = load_nist_sigver_vectors(scheme, hash_algorithm)
        wycheproof = load_wycheproof_vectors(scheme, hash_algorithm)
        return cls(scheme, hash_algorithm, nist, wycheproof)
