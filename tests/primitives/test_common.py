"""Module to test crypto_condor.primitives.common."""

from hashlib import sha256
from pathlib import Path

import pytest

from crypto_condor.primitives import SHA
from crypto_condor.primitives.common import Console, Results, ResultsDict


class TestConsole:
    """Tests for the Console class."""

    def test_filename_none(self, tmp_path: Path):
        """Tests passing None as filename.

        The expected behaviour is that the user is not prompted for a filename.
        """
        rd = SHA.test(lambda msg: sha256(msg).digest(), SHA.Algorithm.SHA_256)
        console = Console()
        assert console.process_results(rd, None)


def test_results_dict():
    """Tests that ResultsDict raises ValueError on duplicate keys."""
    rd1 = ResultsDict()
    rd2 = ResultsDict()

    res1 = Results("AES", "test", "description", {"mode": "ECB"})
    res2 = Results("AES", "test", "description", {"mode": "ECB"})

    rd1.add(res1)
    with pytest.raises(ValueError):
        rd1.add(res2)

    rd2.add(res1)
    with pytest.raises(ValueError):
        rd1.update(rd2)

    with pytest.raises(ValueError):
        rd1 |= rd2
