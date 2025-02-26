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
        rd = SHA.test_digest(lambda msg: sha256(msg).digest(), SHA.Algorithm.SHA_256)
        console = Console()
        assert console.process_results(rd, None)


class TestResultsDict:
    """Tests for :class:`crypto_condor.primitives.common.ResultsDict`."""

    def test_duplicate_keys(self):
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

    def test_fail_if_empty(self):
        """Tests that ``fail_if_empty`` parameter works."""
        res = Results.new("empty", [])
        assert res.check()
        assert not res.check(empty_as_fail=True)

        rd = ResultsDict()
        assert rd.check()

        rd.add(res)
        assert rd.check()
        assert not rd.check(fail_if_empty=True)
