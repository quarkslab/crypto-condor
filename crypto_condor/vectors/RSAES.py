"""Test vectors for RSAES."""

import json
import logging
from importlib import resources
from typing import TypedDict

import attrs
import strenum

# --------------------------- Module --------------------------------------------------
logger = logging.getLogger(__name__)


# --------------------------- Enums ---------------------------------------------------
class Scheme(strenum.StrEnum):
    """RSA encryption schemes."""

    OAEP = "RSAES-OAEP"
    PKCS = "RSAES-PKCS1-v1_5"


class Hash(strenum.StrEnum):
    """Available hash functions."""

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


# --------------------------- Files ---------------------------------------------------
_WYCHEPROOF_ENC_PKCS_FILES = [
    "rsa_pkcs1_2048_test.json",
    "rsa_pkcs1_3072_test.json",
    "rsa_pkcs1_4096_test.json",
]
"""List of available Wycheproof vectors."""

_WYCHEPROOF_ENC_OAEP_FILES: dict[str, dict[str, list[str]]] = {
    "SHA-1": {
        "SHA-1": [
            "rsa_oaep_2048_sha1_mgf1sha1_test.json",
        ]
    },
    "SHA-224": {
        "SHA-1": [
            "rsa_oaep_2048_sha224_mgf1sha1_test.json",
        ],
        "SHA-224": [
            "rsa_oaep_2048_sha224_mgf1sha224_test.json",
        ],
    },
    "SHA-256": {
        "SHA-1": [
            "rsa_oaep_2048_sha256_mgf1sha1_test.json",
            "rsa_oaep_3072_sha256_mgf1sha1_test.json",
            "rsa_oaep_4096_sha256_mgf1sha1_test.json",
        ],
        "SHA-256": [
            "rsa_oaep_2048_sha256_mgf1sha256_test.json",
            "rsa_oaep_3072_sha256_mgf1sha256_test.json",
            "rsa_oaep_4096_sha256_mgf1sha256_test.json",
        ],
    },
    "SHA-384": {
        "SHA-1": [
            "rsa_oaep_2048_sha384_mgf1sha1_test.json",
        ],
        "SHA-384": [
            "rsa_oaep_2048_sha384_mgf1sha384_test.json",
        ],
    },
    "SHA-512": {
        "SHA-1": [
            "rsa_oaep_2048_sha512_mgf1sha1_test.json",
            "rsa_oaep_3072_sha512_mgf1sha1_test.json",
            "rsa_oaep_4096_sha512_mgf1sha1_test.json",
        ],
        "SHA-512": [
            "rsa_oaep_2048_sha512_mgf1sha512_test.json",
            "rsa_oaep_3072_sha512_mgf1sha512_test.json",
            "rsa_oaep_4096_sha512_mgf1sha512_test.json",
        ],
    },
}
"""Available Wycheproof vectors, indexed by hash function then by MGF1 hash function."""


# --------------------------- Wycheproof ----------------------------------------------
class RsaWycheproofEncTest(TypedDict):
    """Represents a single Wycheproof decryption test."""

    tcId: int
    comment: str
    msg: str
    ct: str
    label: str
    result: str
    flags: list[str]


class RsaWycheproofEncGroup(TypedDict):
    """Represents a single Wycheproof decryption group."""

    d: str
    e: str
    keysize: int
    mgf: str
    mgfSha: str
    n: str
    privateKeyPem: str
    privateKeyPkcs8: str
    sha: str
    tests: list[RsaWycheproofEncTest]


class RsaWycheproofEncVectors(TypedDict):
    """Represents a file of Wycheproof decryption vectors."""

    algorithm: str
    numberOfTests: int
    header: list[str]
    testGroups: list[RsaWycheproofEncGroup]


def load_wycheproof_vectors(
    scheme: Scheme, hash_algorithm: Hash | None = None, mgf_hash: Hash | None = None
) -> dict[str, RsaWycheproofEncVectors] | None:
    """Loads Wycheproof test vectors.

    Args:
        scheme: The scheme of the test vectors to load.
        hash_algorithm: The hash algorithm used to generate the test vectors.
        mgf_hash: The MGF1 hash algorithm used to generate RSAES-OAEP vectors, None for
            other schemes.

    Returns:
        A dictionary of test vectors, indexed by the names of the files loaded, or None
        if there aren't vectors for the given parameters.
    """
    rsc = resources.files("crypto_condor")
    vectors_dir = rsc / "vectors/_rsa/wycheproof"
    files: list[str] | None
    match scheme:
        case Scheme.PKCS:
            files = _WYCHEPROOF_ENC_PKCS_FILES
        case Scheme.OAEP:
            _hash_files = _WYCHEPROOF_ENC_OAEP_FILES.get(str(hash_algorithm), dict())
            files = _hash_files.get(str(mgf_hash), None)
    if files is None:
        return None
    vectors = dict()
    for filename in files:
        file = vectors_dir / filename
        data = json.loads(file.read_text())
        vectors[filename] = data
    return vectors


# --------------------------- Vectors -------------------------------------------------
@attrs.frozen
class RsaDecVectors:
    """RSA vectors for ciphertext decryption.

    Do not instantiate directly, use :meth:`load`.

    Args:
        scheme: The encryption scheme of the test vectors.
        hash_algorithm: (RSAES-OAEP only) The hash algorithm used to generate the
            vectors.
        mgf_hash: (RSAES-OAEP only) The MGF1 hash algorithm used to generate the
            vectors.
        wycheproof: The loaded Wycheproof vectors. None if there are no vectors
            available for the given hash algorithm and MGF1 hash, if applicable.

    Example:
        Using :meth:`load` to load the test vectors:

        >>> from crypto_condor.vectors.RSAES import Scheme, Hash, RsaDecVectors
        >>> scheme = Scheme.PKCS
        >>> hash_algorithm = Hash.SHA_256
        >>> vectors = RsaDecVectors.load(scheme, hash_algorithm)
    """

    scheme: Scheme
    hash_algorithm: Hash | None
    mgf_hash: Hash | None
    wycheproof: dict[str, RsaWycheproofEncVectors] | None

    @classmethod
    def load(
        cls,
        scheme: Scheme,
        hash_algorithm: Hash | None = None,
        mgf_hash: Hash | None = None,
    ):
        """Loads RSAES decryption vectors.

        Args:
            scheme: The encryption scheme to get vectors of.
            hash_algorithm: (RSAES-OAEP only) The hash algorithm used to generate the
                ciphertexts.
            mgf_hash: (RSAES-OAEP only) The MGF1 hash algorithm used to generate the
                ciphertexts. If None, the same one as :attr:`hash_algorithm` is used.

        Returns:
            An instance of :class:`RsaDecVectors`.
        """
        # If OAEP and no mgf_hash was given, use the same as hash_algorithm.
        if scheme == Scheme.OAEP:
            if mgf_hash is None:
                mgf_hash = hash_algorithm
            wycheproof = load_wycheproof_vectors(scheme, hash_algorithm, mgf_hash)
        else:
            wycheproof = load_wycheproof_vectors(scheme, hash_algorithm)
        return cls(scheme, hash_algorithm, mgf_hash, wycheproof)
