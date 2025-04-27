"""Module for PLACEHOLDER."""

import importlib
import inspect
import json
import logging
import sys
from pathlib import Path
from typing import Protocol

import attrs
import cffi
import strenum
from rich.progress import track

from crypto_condor.primitives.common import Results, ResultsDict, TestInfo, TestType
from crypto_condor.vectors._LCPLACEHOLDER.LCPLACEHOLDER_pb2 import (
    CapPLACEHOLDERTest,
    CapPLACEHOLDERVectors,
)
from crypto_condor.vectors.LCPLACEHOLDER import Paramset

# --------------------------- Module --------------------------------------------------

logger = logging.getLogger(__name__)


def __dir__():  # pragma: no cover
    return [
        # Enums
        Wrapper.__name__,
        # Protocols
        PLACEHOLDER.__name__,
        # Test functions
        # Runners
        test_wrapper.__name__,
        test_wrapper_python.__name__,
    ]


# --------------------------- Enums ---------------------------------------------------


class Wrapper(strenum.StrEnum):
    """Supported languages for wrappers."""

    pass


# --------------------------- Vectors -------------------------------------------------


def _load_vectors(paramset: Paramset, compliance: bool, resilience: bool) -> list[CapPLACEHOLDERVectors]:
    """Loads vectors for a given parameter set.

    Args:
        paramset:
            The parameter set to load vectors of.

    Returns:
        A list of vectors.
    """
    vectors_dir = importlib.resources.files("crypto_condor") / "vectors/_LCPLACEHOLDER"
    vectors = list()

    sources_file = vectors_dir / "LCPLACEHOLDER.json"
    with sources_file.open("r") as file:
        sources = json.load(file)

    for filename in sources.get(str(paramset)):
        vectors_file = vectors_dir / "pb2" / filename
        _vec = CapPLACEHOLDERVectors()
        logger.debug("Loading PLACEHOLDER vectors from %s", str(filename))
        try:
            _vec.ParseFromString(vectors_file.read_bytes())
        except Exception:
            logger.error("Failed to load PLACEHOLDER vectors from %s", str(filename))
            logger.debug("Exception caught while loading vectors", exc_info=True)
        if _vec.compliance and compliance:
            vectors.append(_vec)
        if not _vec.compliance and resilience:
            vectors.append(_vec)

    return vectors


# --------------------------- Protocols -----------------------------------------------


class Operation(Protocol):
    """Represents an operation of PLACEHOLDER."""


# --------------------------- Dataclasses----------------------------------------------


@attrs.define
class OperationData:
    """Debug data for <operation> tests."""

    def __str__(self):
        """Returns a string representation of the fields in use."""
        raise NotImplementedError


# --------------------------- Test functions ------------------------------------------

# --------------------------- Runners -------------------------------------------------


def test_wrapper_python(
    wrapper: Path, compliance: bool, resilience: bool
) -> ResultsDict:
    """Tests a PLACEHOLDER Python wrapper.

    Args:
        wrapper:
            A path to the wrapper to test.
        compliance:
            Whether to use compliance test vectors.
        resilience:
            Whether to use resilience test vectors.
    """
    logger.info("Running Python PLACEHOLDER wrapper: '%s'", str(wrapper.name))
    sys.path.insert(0, str(wrapper.parent.absolute()))
    already_imported = wrapper.stem in sys.modules.keys()
    try:
        LCPLACEHOLDER_wrapper = importlib.import_module(wrapper.stem)
    except ModuleNotFoundError as error:
        logger.error("Can't import wrapper: '%s'", str(error))
        raise
    if already_imported:
        logger.debug("Reloading PLACEHOLDER wrapper: '%s'", wrapper.stem)
        LCPLACEHOLDER_wrapper = importlib.reload(LCPLACEHOLDER_wrapper)

    rd = ResultsDict()

    for func, _ in inspect.getmembers(LCPLACEHOLDER_wrapper, inspect.isfunction):
        match func.split("_"):
            case ["CC", "PLACEHOLDER", *_]:
                logger.warning("Invalid function CC_PLACEHOLDER %s", func)
                continue
            case _:
                pass
    return rd


def test_wrapper(wrapper: Path, compliance: bool, resilience: bool) -> ResultsDict:
    """Tests a PLACEHOLDER wrapper.

    Args:
        wrapper:
            The wrapper to test.
        compliance:
            Whether to use compliance test vectors.
        resilience:
            Whether to use resilience test vectors.

    Raises:
        FileNotFoundError:
            If the wrapper is not found.
    """
    if not wrapper.is_file():
        raise FileNotFoundError(f"Wrapper {str(wrapper)} not found")

    match wrapper.suffix:
        case ".py":
            return test_wrapper_python(wrapper, compliance, resilience)
        case _:
            raise ValueError(f"No runner for '{wrapper.suffix}' wrappers")
