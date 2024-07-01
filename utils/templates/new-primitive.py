"""Module for PLACEHOLDER."""

import importlib
import logging
from pathlib import Path
from typing import Protocol

import attrs
import strenum
from rich.progress import track

from crypto_condor.primitives.common import Results, ResultsDict, TestInfo, TestType

# --------------------------- Module --------------------------------------------------

logger = logging.getLogger(__name__)


def __dir__():  # pragma: no cover
    return [
        # Enums
        Wrapper.__name__,
        # Vectors
        PLACEHOLDERVectors.__name__,
        # Protocols
        PLACEHOLDER.__name__,
        # Test functions
        # Runners
        run_wrapper.__name__,
    ]


# --------------------------- Enums ---------------------------------------------------


class Wrapper(strenum.StrEnum):
    """Supported languages for wrappers."""

    pass


# --------------------------- Vectors -------------------------------------------------


@attrs.define
class PLACEHOLDERVectors:
    """Test vectors for PLACEHOLDER.

    Do not instantiate directly, use :meth:`load`.
    """

    @classmethod
    def load(self):
        """Loads test vectors for PLACEHOLDER."""
        raise NotImplementedError


# --------------------------- Protocols -----------------------------------------------


class PLACEHOLDER(Protocol):
    """Represents an implementation of PLACEHOLDER."""


# --------------------------- Dataclasses----------------------------------------------


@attrs.define
class PLACEHOLDERData:
    """Debug data for PLACEHOLDER tests."""

    def __str__(self):
        """Returns a string representation of the fields in use."""
        raise NotImplementedError


# --------------------------- Test functions ------------------------------------------

# --------------------------- Runners -------------------------------------------------


def run_wrapper():
    """Runs a PLACEHOLDER wrapper."""
    raise NotImplementedError
