"""Test vectors for ChaCha20."""

import json
import logging
from importlib import resources
from typing import TypedDict

import attrs
import strenum

logger = logging.getLogger(__name__)


# --------------------------- Enums ---------------------------------------------------


class Mode(strenum.StrEnum):
    """Supported ChaCha20 modes of operation."""

    CHACHA20_POLY1305 = "CHACHA20-POLY1305"
    CHACHA20 = "CHACHA20"


# --------------------------- Exceptions ----------------------------------------------


class ChaCha20VectorsError(Exception):
    """Exception for errors when loading or parsing vectors."""

    pass


# --------------------------- Vectors -------------------------------------------------


class ChaCha20WycheproofTest(TypedDict):
    """Represents a single ChaCha20 Wycheproof test."""

    tdId: int
    comment: str
    key: str
    iv: str
    aad: str
    msg: str
    ct: str
    tag: str
    result: str
    flags: list[str]


class ChaCha20WycheproofGroup(TypedDict):
    """Represents a group of Wycheproof tests."""

    ivSize: int
    keySize: int
    tagSize: int
    tests: list[ChaCha20WycheproofTest]


class ChaCha20WycheproofVectors(TypedDict):
    """Represents a file of Wycheproof ChaCha20 vectors."""

    algorithm: str
    numberOfTests: int
    header: list[str]
    notes: dict[str, str]
    testGroups: list[ChaCha20WycheproofGroup]


def load_wycheproof_vectors(mode: Mode) -> ChaCha20WycheproofVectors:
    """Loads Wycheproof ChaCha20 vectors.

    Args:
        mode:
            The mode of operation.

    Returns:
        The corresponding Wycheproof test vectors.

    Raises:
        ChaCha20VectorsError:
            Raised if an error occurred while loading the vectors.
    """
    vectors_dir = resources.files("crypto_condor") / "vectors/_chacha20/wycheproof"
    if mode == Mode.CHACHA20_POLY1305:
        filename = "chacha20_poly1305_test.json"
    else:
        filename = "chacha20_test.json"
    vectors_file = vectors_dir / filename

    if not vectors_file.is_file():
        raise ChaCha20VectorsError(
            "Wycheproof vectors file %s not found", str(vectors_file)
        )

    try:
        vectors = json.loads(vectors_file.read_bytes())
    except OSError as error:
        logger.exception("Could not open %s", str(vectors_file))
        raise ChaCha20VectorsError(
            "Error loading Wycheproof vectors: %s", str(error)
        ) from error
    except json.JSONDecodeError as error:
        logger.exception("Could not JSON-decode %s", str(vectors_file))
        raise ChaCha20VectorsError(
            "Error loading Wycheproof vectors: %s", str(error)
        ) from error

    return vectors


@attrs.define
class ChaCha20Vectors:
    """A class to group ChaCha20 test vectors.

    Do not instantiate directly, use :meth:`load`.

    Args:
        mode:
            The mode of operation.
        wycheproof:
            The corresponding Wycheproof vectors.
    """

    mode: Mode
    wycheproof: ChaCha20WycheproofVectors

    @classmethod
    def load(cls, mode: Mode):
        """Loads ChaCha20 test vectors.

        Args:
            mode:
                The mode of operation.

        Returns:
            An :class:`ChaCha20Vectors` instance with the corresponding test vectors.

        Raises:
            ChaCha20VectorError:
                Raised when an error occurred while loading the vectors.
        """
        wycheproof = load_wycheproof_vectors(mode)
        return cls(mode, wycheproof)
