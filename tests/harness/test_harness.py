"""Tests for :mod:`crypto_condor.primitives.lib_hook`."""

import subprocess
import sys
from pathlib import Path

import pytest

from crypto_condor import harness
from crypto_condor.primitives.common import Console

console = Console()
# We assume that tests are run from the root of the repository.
ROOT_DIR = Path("tests/harness")


@pytest.mark.skipif(sys.platform != "linux", reason="dlopen's library in .local/share")
@pytest.mark.parametrize("primitive", ["AES", "MLDSA", "MLKEM", "SHAKE"])
def test_harness(primitive: str):
    """Tests harnesses with :func:`crypto_condor.harness.test_harness`."""
    # Compile the hook
    subprocess.run(["make", "-C", ROOT_DIR, f"{primitive}.harness.so"], check=True)

    results = harness.test_harness(ROOT_DIR / f"{primitive}.harness.so")

    # Clean up
    subprocess.run(["make", "-C", ROOT_DIR, "clean"], check=True)

    console.print_results(results)
    assert results.check()
