"""Module to test crypto_condor.primitives.common."""

from hashlib import sha256
from pathlib import Path

from crypto_condor.primitives import SHA
from crypto_condor.primitives.common import Console


class TestConsole:
    """Tests for the Console class."""

    def test_filename_none(self, tmp_path: Path):
        """Tests passing None as filename.

        The expected behaviour is that the user is not prompted for a filename.
        """
        rd = SHA.test(lambda msg: sha256(msg).digest(), SHA.Algorithm.SHA_256)
        console = Console()
        assert console.process_results(rd, None)
