"""Module for PLACEHOLDER."""

from importlib import resources
import inspect
import json
import logging
from pathlib import Path
from typing import Protocol

import attrs
import cffi
import strenum
from rich.progress import track

from crypto_condor.primitives.common import (
    Results,
    ResultsDict,
    TestInfo,
    TestType,
    _load_python_harness,
)
from crypto_condor.vectors._LCPLACEHOLDER.LCPLACEHOLDER_pb2 import (
    CapPLACEHOLDERTest,
    CapPLACEHOLDERVectors,
)
from crypto_condor.vectors.LCPLACEHOLDER import Paramset

# -------------------------------------------------------------------------------------
# Module
# -------------------------------------------------------------------------------------

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


# -------------------------------------------------------------------------------------
# Enums
# -------------------------------------------------------------------------------------


class Wrapper(strenum.StrEnum):
    """Supported languages for wrappers."""

    pass


# -------------------------------------------------------------------------------------
# Test vectors
# -------------------------------------------------------------------------------------


def _load_vectors(paramset: Paramset, compliance: bool, resilience: bool) -> list[CapPLACEHOLDERVectors]:
    """Loads vectors for a given parameter set.

    Args:
        paramset:
            The parameter set to load vectors of.

    Returns:
        A list of vectors.
    """
    vectors_dir = resources.files("crypto_condor") / "vectors/_LCPLACEHOLDER"
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
            continue
        if _vec.compliance and compliance:
            vectors.append(_vec)
        if not _vec.compliance and resilience:
            vectors.append(_vec)

    if not vectors:
        logger.error(
            "No PLACEHOLDER test vectors loaded for param=%s, compliance=%s, resilience=%s",
            str(paramset),
            compliance,
            resilience,
        )

    return vectors


# -------------------------------------------------------------------------------------
# Protocols
# -------------------------------------------------------------------------------------


class Operation(Protocol):
    """Represents an operation of PLACEHOLDER."""

    def __call__(self):  # pragma: no cover
        """FIXME."""

        ...


# -------------------------------------------------------------------------------------
# Dataclasses
# -------------------------------------------------------------------------------------


@attrs.define
class OperationData:
    """Debug data for <operation> tests."""

    def __str__(self):
        """Returns a string representation of the fields in use."""
        raise NotImplementedError

    @classmethod
    def from_test(cls, test: CapPLACEHOLDERTest):
        """Returns an instance of OperationData from a test."""
        raise NotImplementedError


# -------------------------------------------------------------------------------------
# Test functions
# -------------------------------------------------------------------------------------

def test_operation(paramset: Paramset, compliance: bool, resilience: bool) -> ResultsDict:
    """FIXME."""
    rd = ResultsDict()

    test_vectors = _load_vectors(paramset, compliance, resilience)
    if not test_vectors:
        return rd

    test: CapPLACEHOLDERTest
    for vectors in test_vectors:
        results = Results.new("FIXME: description", ["paramset"], vectors)
        rd.add(results, extra_values=[vectors.source])

        for test in track(vectors.tests, "FIXME: description"):
            data = OperationData.from_test(test)
            info = TestInfo.new_from_test(test, vectors.compliance, data)

            # FIXME: test logic

            results.add(info)

    return rd

# -------------------------------------------------------------------------------------
# Harnesses
# -------------------------------------------------------------------------------------


def test_harness_python(
    harness: Path, compliance: bool, resilience: bool
) -> ResultsDict:
    """Tests a PLACEHOLDER Python harness.

    Args:
        harness:
            A path to the harness to test.
        compliance:
            Whether to use compliance test vectors.
        resilience:
            Whether to use resilience test vectors.
    """
    rd = ResultsDict()

    module_harness = _load_python_harness(harness)
    if module_harness is None:
        return rd

    for funcname, _ in inspect.getmembers(module_harness, inspect.isfunction):
        func = getattr(module_harness, funcname)
        match funcname.split("_"):
            case ["CC", "PLACEHOLDER", *_]:
                logger.warning("Invalid function CC_PLACEHOLDER %s", funcname)
                continue

    return rd


def test_harness(harness: Path, compliance: bool, resilience: bool) -> ResultsDict:
    """Tests a PLACEHOLDER harness.

    Args:
        harness:
            The harness to test.
        compliance:
            Whether to use compliance test vectors.
        resilience:
            Whether to use resilience test vectors.

    Raises:
        FileNotFoundError:
            If the harness is not found.
    """
    if not harness.is_file():
        raise FileNotFoundError(f"harness {str(harness)} not found")

    match harness.suffix:
        case ".py":
            return test_harness_python(harness, compliance, resilience)
        case _:
            raise ValueError(f"No test for '{harness.suffix}' harnesss")
