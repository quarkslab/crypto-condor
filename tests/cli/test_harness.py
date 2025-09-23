"""Tests for the `test wrapper` command.

This new module is for (slowly) migrating the old Python wrappers to Python harnesses.
"""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from crypto_condor.cli.main import app

runner = CliRunner()


class TestEd25519:
    """Tests for Ed25519 harnesses."""

    @pytest.mark.parametrize(("language", "example"), [("Python", "1")])
    def test_examples(self, language: str, example: str, tmp_path: Path):
        """Tests Ed25519 harness examples."""
        with runner.isolated_filesystem(tmp_path):
            result = runner.invoke(
                app,
                ["get-wrapper", "ed25519", "--language", "Python", "--example", "1"],
            )
            assert result.exit_code == 0, "Failed to get harness example"
            args = ["test", "wrapper", "ed25519", "ed25519_harness.py", "--resilience"]
            result = runner.invoke(app, args)
            print(result.output)
            assert result.exit_code == 0


class TestX25519:
    """Tests for X25519 harnesses."""

    @pytest.mark.parametrize(("language", "example"), [("Python", "1")])
    def test_examples(self, language: str, example: str, tmp_path: Path):
        """Tests X25519 harness examples."""
        with runner.isolated_filesystem(tmp_path):
            result = runner.invoke(
                app,
                ["get-wrapper", "x25519", "--language", "Python", "--example", "1"],
            )
            assert result.exit_code == 0, "Failed to get harness example"
            args = ["test", "wrapper", "x25519", "x25519_harness.py", "--resilience"]
            result = runner.invoke(app, args)
            print(result.output)
            assert result.exit_code == 0
