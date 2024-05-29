"""Module to test the CLI for TestU01."""

from pathlib import Path

from typer.testing import CliRunner

from crypto_condor.cli.main import app

runner = CliRunner()


def test_urandom():
    """Tests running TestU01 with a sample file.

    The file is generated from /dev/urandom.
    """
    urandom_file = Path(__file__).parent.parent / "data/urandom.bin"
    result = runner.invoke(app, ["testu01", str(urandom_file), "--no-save"])
    assert result.exit_code == 0, "Error running command"


def test_where():
    """Tests testu01 --where."""
    result = runner.invoke(app, ["testu01", "--where"])
    assert result.exit_code == 0, "Error running command"
