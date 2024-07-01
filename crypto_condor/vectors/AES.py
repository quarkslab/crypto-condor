"""Test vectors for AES."""

import enum
import json
import logging
from importlib import resources
from typing import TypedDict

import attrs
import strenum

from crypto_condor.vectors._aes.aes_pb2 import AesNistVectors

logger = logging.getLogger(__name__)

# --------------------------- Enums ---------------------------------------------------


class KeyLength(enum.IntEnum):
    """Supported key lengths.

    AES has three different key lengths: 128, 192, and 256 bits. Since users may want to
    test a specific key length, this enum defines these three options alongside the
    :attr:`KeyLength.ALL` option to test all three.
    """

    ALL = 0
    AES128 = 128
    AES192 = 192
    AES256 = 256


class Mode(strenum.StrEnum):
    """Supported AES modes of operation.

    The AES primitive is used with a variety of modes of operation. This enum defines
    those that are supported by crypto-condor.
    """

    ECB = "ECB"
    CBC = "CBC"
    CBC_PKCS7 = "CBC-PKCS7"
    CFB = "CFB"
    CFB8 = "CFB8"
    CFB128 = "CFB128"
    CTR = "CTR"
    GCM = "GCM"
    CCM = "CCM"

    @classmethod
    def classic_modes(cls):
        """Returns a list of all classic modes."""
        return [e for e in cls if str(e) not in {"GCM", "CCM"}]


# --------------------------- Exceptions ----------------------------------------------


class AesVectorsError(Exception):
    """Exception for errors importing AES vectors."""

    pass


# --------------------------- Vectors -------------------------------------------------


class AesWycheproofTest(TypedDict):
    """Represents a single AES Wycheproof test."""

    tcId: int
    comment: str
    key: str
    iv: str
    aad: str
    msg: str
    ct: str
    tag: str
    result: str
    flags: list[str]


class AesWycheproofGroup(TypedDict):
    """Represents a Wycheproof AES test group."""

    ivSize: int
    keySize: int
    tagSize: int
    tests: list[AesWycheproofTest]


class AesWycheproofVectors(TypedDict):
    """Represents a Wycheproof file of AES test vectors."""

    algorithm: str
    numberOfTests: int
    header: list[str]
    notes: dict[str, str]
    testGroups: list[AesWycheproofGroup]


def load_wycheproof_vectors(mode: Mode) -> AesWycheproofVectors | None:
    """Loads Wycheproof test vectors.

    Args:
        mode:
            The mode of operation to get test vectors of.

    Returns:
        The corresponding :class:`AesWycheproofVectors` or None if there aren't
        Wycheproof vectors for the given mode of operation.

    Raises:
        OSError:
            If an error occurred when opening or reading the file.
        json.JSONDecodeError:
            If the vector files has invalid JSON.
    """
    match mode:
        case "GCM":
            filename = "aes_gcm_test.json"
        case "CCM":
            filename = "aes_ccm_test.json"
        case "CBC-PKCS7":
            filename = "aes_cbc_pkcs5_test.json"
        case _:
            return None

    rsc = resources.files("crypto_condor")
    file = rsc / "vectors/_aes/wycheproof" / filename
    try:
        vectors = json.loads(file.read_text())
    except OSError as err:
        logger.exception("Could not open %s", str(file))
        raise AesVectorsError("Error reading vectors") from err
    except json.JSONDecodeError as err:
        logger.exception("Could not JSON-decode %s", str(file))
        raise AesVectorsError("Error parsing vectors") from err

    return vectors


def load_nist_vectors(
    mode: Mode, key_length: KeyLength
) -> dict[int, list[AesNistVectors]]:
    """Gets NIST test vectors from a list of shortened filenames.

    Args:
        mode:
            The mode of operation to get test vectors of.
        key_length:
            The key length in bits. NIST test vectors can be selected by key length.

    Returns:
        A dictionary containing list of NIST vectors indexed by key length.
    """
    # CFB is an alias of CFB128.
    if mode == Mode.CFB:
        mode = Mode.CFB128

    # CBC-PKCS7 uses the same NIST vectors as CBC.
    if mode == Mode.CBC_PKCS7:
        mode = Mode.CBC

    vectors: dict[int, list[AesNistVectors]]

    if key_length == KeyLength.ALL:
        vectors = {128: list(), 192: list(), 256: list()}
    else:
        vectors = {key_length: list()}

    suffixes = ["txt", "gfsbox", "keysbox", "varkey", "mmt"]
    """Suffixes of the filenames of test vectors."""

    match mode:
        case Mode.ECB | Mode.CBC | Mode.CFB8 | Mode.CFB128:
            files = {
                key_length: [
                    f"aes_{str(mode).lower()}_{key_length}_{suffix}"
                    for suffix in suffixes
                ]
                for key_length in vectors.keys()
            }
        case Mode.CTR:
            # Similar to above except it does not use suffixes.
            files = {
                key_length: [f"aes_ctr_{key_length}"] for key_length in vectors.keys()
            }
        case Mode.GCM:
            # Similar to the first case, but with only two suffixes.
            files = {
                key_length: [f"aes_gcm_{key_length}_enc", f"aes_gcm_{key_length}_dec"]
                for key_length in vectors.keys()
            }
        case Mode.CCM:
            # No NIST vectors.
            files = dict()

    vectors_dir = resources.files("crypto_condor") / "vectors/_aes/dat"

    for keylen, filenames in files.items():
        for filename in filenames:
            v = AesNistVectors()
            file = vectors_dir / f"{filename}.dat"
            with file.open("rb") as fd:
                v.ParseFromString(fd.read())
            vectors[keylen].append(v)

    return vectors


@attrs.define
class AesVectors:
    """A class to load test vectors for AES.

    Do not instantiate directly, use :meth:`load`.

    Depending on the mode, NIST and Wycheproof test vectors can be loaded.

    Args:
        mode:
            The mode of operation to get test vectors of.
        key_length:
            The key length in bits. NIST vectors can be selected by key length.
        nist:
            A dictionary of NIST test vectors, indexed by key length.
        wycheproof:
            An instance of :class:`AesWycheproofVectors`, if there are
            Wycheproof vectors for the given mode of operation.

    Example:
        To load the test vectors for AES-128-ECB:

        >>> from crypto_condor.vectors.AES import KeyLength, Mode, AesVectors
        >>> vectors = AesVectors.load(Mode.ECB, KeyLength.AES128)

        To test for compliance use :attr:`nist` vectors, which are grouped by key
        length.

        >>> for key_length in vectors.nist:
        ...     print(int(key_length))
        128

        Some modes do not have resilience test vectors.

        >>> vectors.wycheproof is None
        True

        Others do.

        >>> vectors = AesVectors.load(Mode.GCM, KeyLength.ALL)
        >>> vectors.wycheproof is not None
        True
    """

    mode: Mode
    key_length: KeyLength
    nist: dict[int, list[AesNistVectors]]
    wycheproof: AesWycheproofVectors | None

    @classmethod
    def load(cls, mode: Mode, key_length: KeyLength = KeyLength.ALL):
        """Loads AES test vectors.

        Args:
            mode:
                The mode of operation to get test vectors of.
            key_length:
                The key length in bits. NIST test vectors can be selected by key length.

        Returns:
            An instance of :class:`AesVectors` with the corresponding vectors.
        """
        nist = load_nist_vectors(mode, key_length)
        wycheproof = load_wycheproof_vectors(mode)

        return cls(mode, key_length, nist, wycheproof)
