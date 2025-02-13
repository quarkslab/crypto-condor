"""Module for testing the 'wrap' command."""

from importlib import resources
from pathlib import Path

import pytest
from typer.testing import CliRunner

from crypto_condor.cli.main import app
from crypto_condor.constants import SUPPORTED_MODES, Primitive

runner = CliRunner()


_with_wrap = set([p for p in Primitive if SUPPORTED_MODES[p]["wrapper"]])
_without_wrap = set([p for p in Primitive]).difference(_with_wrap)

# pytest-xdist workaround
PRIMITIVES_WITH_WRAP: list[Primitive] = sorted(_with_wrap)
PRIMITIVES_WITHOUT_WRAP: list[Primitive] = sorted(_without_wrap)


def _get_wrappers():
    """Returns a list of (primitive, language) tuples of available wrappers."""
    wrappers = list()
    wrappers_dir = resources.files("crypto_condor") / "resources/wrappers"
    assert wrappers_dir.is_dir(), "Wrappers directory is missing"
    for primitive in PRIMITIVES_WITH_WRAP:
        prim_dir = wrappers_dir / str(primitive)
        assert prim_dir.is_dir(), f"Directory for {str(primitive)} is missing"
        assert primitive.get_languages() is not None, (
            f"{str(primitive)} has no wrapper languages defined"
        )
        wrappers.extend(
            [(str(primitive), str(lang)) for lang in primitive.get_languages()]
        )
    return wrappers


WRAPPERS = _get_wrappers()


@pytest.mark.parametrize("primitive,language", WRAPPERS)
def test_supported_primitive(primitive: str, language: str, tmp_path: Path):
    """Tests the wrap command with supported primitives."""
    result = runner.invoke(
        app,
        ["get-wrapper", primitive, "-d", str(tmp_path), "-l", language],
    )
    assert result.exit_code == 0


@pytest.mark.parametrize("primitive", PRIMITIVES_WITHOUT_WRAP)
def test_unsupported_primitive(primitive: str, tmp_path: Path):
    """Tests the wrap command with unsupported primitives."""
    result = runner.invoke(app, ["get-wrapper", primitive, "--dir", str(tmp_path)])
    assert result.exit_code != 0
    assert primitive in result.stdout


@pytest.mark.parametrize("primitive", PRIMITIVES_WITH_WRAP)
def test_unsupported_language(primitive: str, tmp_path: Path):
    """Tests the wrap command with a supported primitive and unsupported language."""
    result = runner.invoke(
        app, ["get-wrapper", primitive, "-d", str(tmp_path), "-l", "javascript"]
    )
    assert result.exit_code != 0


@pytest.mark.parametrize("primitive,language", WRAPPERS)
def test_force(primitive: str, language: str, tmp_path: Path):
    """Tests using the --force option.

    Calls wrap once for the initial setup, then again to check for a failure to
    overwrite the first file, and then a third time with --force to overwrite
    it.
    """
    result = runner.invoke(
        app,
        ["get-wrapper", primitive, "-d", str(tmp_path), "-l", language],
    )
    assert result.exit_code == 0

    result = runner.invoke(
        app,
        ["get-wrapper", primitive, "-d", str(tmp_path), "-l", language],
    )
    assert result.exit_code != 0

    result = runner.invoke(
        app,
        [
            "get-wrapper",
            primitive,
            "-d",
            str(tmp_path),
            "-l",
            language,
            "--force",
        ],
    )
    assert result.exit_code == 0


def test_list_languages():
    """Tests get-wrapper --list."""
    result = runner.invoke(app, ["get-wrapper", "--list"])
    assert result.exit_code == 0, "Error running command"
