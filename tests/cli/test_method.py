"""Module to test the 'method' command."""

import os
import warnings
from pathlib import Path

import pytest
from typer.testing import CliRunner

from crypto_condor.cli.main import app
from crypto_condor.constants import SUPPORTED_MODES, Primitive

runner = CliRunner()


# Different sets of primitives for testing.
_with_method = set([p for p in Primitive if SUPPORTED_MODES[p]["method"]])
_without_method = set([p for p in Primitive]).difference(_with_method)

# pytest-xdist workaround
PRIMITIVES_WITH_METHOD = sorted(_with_method)
PRIMITIVES_WITHOUT_METHOD = sorted(_without_method)


@pytest.mark.parametrize("primitive", PRIMITIVES_WITHOUT_METHOD)
def test_missing_documentation(primitive: str, tmp_path: Path):
    """Test to check primitives without documentation and warn about them."""
    dst = tmp_path / f"{primitive}.md"
    result = runner.invoke(app, ["method", primitive, "--out", str(dst)])
    assert result.exit_code != 0
    warnings.warn(f"Missing documentation for {primitive}", stacklevel=0)


@pytest.mark.parametrize("primitive", PRIMITIVES_WITH_METHOD)
def test_save_to_file(primitive: str, tmp_path: Path):
    """Tests saving a guide to a file."""
    # Using isolated FS to ensure the files should not exist beforehand.
    with runner.isolated_filesystem(tmp_path):
        result = runner.invoke(app, ["method", str(primitive)])
        file = Path(f"{str(primitive)}.md")
        assert result.exit_code == 0, "Invoke failed"
        assert file.is_file(), "File does not exist"
        assert file.stat().st_size > 0, "File is empty"


@pytest.mark.parametrize("primitive", PRIMITIVES_WITH_METHOD)
def test_save_to_custom_file(primitive: str, tmp_path: Path):
    """Tests saving a guide to a given filename."""
    dst = tmp_path / f"guide-for-{primitive}.md"
    result = runner.invoke(app, ["method", str(primitive), "--out", str(dst)])
    assert result.exit_code == 0, "Invoke failed"
    assert dst.is_file(), "File does not exist"
    assert dst.stat().st_size > 0, "File is empty"


@pytest.mark.parametrize("primitive", PRIMITIVES_WITH_METHOD)
def test_fail_to_save(primitive: str, tmp_path: Path):
    """Tests saving a guide to a read-only file."""
    dst = tmp_path / f"{primitive}.md"
    dst.touch(0o444)

    # Somehow the file may be writeable in the CI, so skip the test if it happens.
    can_write = os.access(str(dst), os.W_OK)
    if can_write:
        warnings.warn("Couldn't set file to read-only, skipping test", stacklevel=0)
        return

    result = runner.invoke(app, ["method", "--primitive", primitive, "--out", str(dst)])
    assert result.exit_code != 0
    assert dst.exists()
    assert dst.read_text() == ""
