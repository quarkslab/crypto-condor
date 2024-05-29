"""Test module for CLI commands.

Groups various commands with little to no options.
"""

import importlib

from typer.testing import CliRunner

from crypto_condor.cli.main import app

runner = CliRunner()


def test_version():
    """Tests the --version option."""
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0, "Error running command"
    assert importlib.metadata.version("crypto-condor") in result.output, "Wrong version"


def test_list():
    """Tests the list command."""
    result = runner.invoke(app, ["list"])
    assert result.exit_code == 0, "Error running command"
