"""Test the TestU01 module."""

from pathlib import Path

from crypto_condor.primitives import TestU01


def test_file():
    """Tests the test_file function with a fixed file."""
    urandom_file = Path(__file__).parent.parent / "data/urandom.bin"
    result = TestU01.test_file(str(urandom_file))

    assert result is not None, "Execution error returned empty result"
    assert result.check()
