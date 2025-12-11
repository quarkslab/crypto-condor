"""Module for testing the 'run' command."""

import warnings
from pathlib import Path

import pytest
from typer.testing import CliRunner

from crypto_condor.cli.main import app
from crypto_condor.constants import SUPPORTED_MODES, Primitive

runner = CliRunner()

PRIMITIVES_WITH_RUN = set(
    [p.lower() for p in Primitive if SUPPORTED_MODES[p]["wrapper"]]
)


def test_aes_example(tmp_path: Path):
    """Tests AES wrapper example."""
    with runner.isolated_filesystem(tmp_path):
        result = runner.invoke(
            app, ["get-wrapper", "AES", "--language", "Python", "--example", "1"]
        )
        assert result.exit_code == 0, "Could not get wrapper example"
        args = [
            "test",
            "wrapper",
            "AES",
            "aes_wrapper_example.py",
            "--no-save",
            "--resilience",
        ]
        result = runner.invoke(app, args)
        print(result.output)
        assert result.exit_code == 0


class TestChaCha20:
    """Tests running ChaCha20 wrappers."""

    @pytest.mark.parametrize("language,example", [("Python", "1")])
    def test_examples(self, language: str, example: str, tmp_path: Path):
        """Tests ChaCha20 wrapper examples."""
        with runner.isolated_filesystem(tmp_path):
            get_wrapper_result = runner.invoke(
                app,
                [
                    "get-wrapper",
                    "ChaCha20",
                    "--language",
                    language,
                    "--example",
                    example,
                ],
            )
            print(get_wrapper_result.output)
            assert get_wrapper_result.exit_code == 0

            args = ["test", "wrapper", "chacha20", "chacha20_wrapper_example.py"]
            result = runner.invoke(app, args)
            print(result.output)
            assert result.exit_code == 0


class TestEcdsa:
    """Tests ECDSA wrappers."""

    def test_cryptography_example(self):
        """Tests the ECDSA cryptography wrapper examples."""
        with runner.isolated_filesystem():
            wrap_result = runner.invoke(
                app,
                [
                    "get-wrapper",
                    "ECDSA",
                    "--language",
                    "Python",
                    "--example",
                    "1",
                    "--force",
                ],
            )
            assert wrap_result.exit_code == 0, "Could not get wrapper"

            args = ["test", "wrapper", "ECDSA", "ecdsa_wrapper_example.py", "--no-save"]

            result = runner.invoke(app, args)
            print(result.output)
            assert result.exit_code == 0


class TestSha:
    """Tests for SHA module."""

    # TODO: add example for C wrapper.
    @pytest.mark.parametrize(("lang", "ex"), [("Python", "1")])
    def test_examples(self, lang: str, ex: str):
        """Tests the SHA wrapper examples."""
        with runner.isolated_filesystem():
            wrap_result = runner.invoke(
                app,
                ["get-wrapper", "SHA", "--language", lang, "--example", ex, "--force"],
            )
            assert wrap_result.exit_code == 0, "Could not get wrapper example"
            args = [
                "test",
                "wrapper",
                "SHA",
                "sha_wrapper_example.py",
                "--no-save",
            ]
            result = runner.invoke(app, args)
            print(result.output)
            assert result.exit_code == 0, "Test failed"


class TestShake:
    """Tests for SHAKE module."""

    def test_shake_examples(self):
        """Tests the SHAKE wrapper examples."""
        with runner.isolated_filesystem():
            wrap_result = runner.invoke(
                app,
                [
                    "get-wrapper",
                    "SHAKE",
                    "--language",
                    "Python",
                    "--example",
                    "1",
                    "--force",
                ],
            )
            if wrap_result.exit_code != 0:
                warnings.warn("Could not get wrapper example", stacklevel=0)
                return

            args = ["test", "wrapper", "SHAKE", "shake_wrapper_example.py", "--no-save"]

            result = runner.invoke(app, args)
            print(result.output)
            assert result.exit_code == 0


class TestRSASSA:
    """Test RSASSA wrappers."""

    def test_example(self):
        """Tests the RSA wrapper example."""
        with runner.isolated_filesystem():
            wrap_result = runner.invoke(
                app, "get-wrapper RSASSA --language Python --example 1 --force"
            )
            assert wrap_result.exit_code == 0, "Could not get wrapper example"

            result = runner.invoke(app, "test wrapper RSASSA rsassa_wrapper_example.py")
            print(result.output)
            assert result.exit_code == 0


class TestRSAES:
    """Test RSAES wrappers."""

    def test_example(self):
        """Tests the RSAES wrapper example."""
        with runner.isolated_filesystem():
            wrap_result = runner.invoke(
                app, "get-wrapper RSAES --language Python --example 1 --force"
            )
            if wrap_result.exit_code != 0:
                warnings.warn("Could not get wrapper example", stacklevel=0)
                return

            result = runner.invoke(app, "test wrapper RSAES rsaes_wrapper_example.py")
            print(result.output)
            assert result.exit_code == 0


class TestHmac:
    """Tests HMAC wrapper."""

    def test_examples(self, tmp_path: Path):
        """Tests HMAC wrapper example."""
        with runner.isolated_filesystem(tmp_path):
            wrap_result = runner.invoke(
                app, "get-wrapper HMAC --language Python --example 1"
            )
            assert wrap_result.exit_code == 0, "Could not get HMAC wrapper"

            args = "test wrapper HMAC hmac_wrapper_example.py --no-save"
            result = runner.invoke(app, args)
            print(result.output)
            assert result.exit_code == 0


class TestECDH:
    """Tests ECDH wrappers."""

    def test_example(self, tmp_path: Path):
        """Tests ECDH wrapper example."""
        with runner.isolated_filesystem(tmp_path):
            args = "get-wrapper ECDH --language Python --example 1"
            wrap_result = runner.invoke(app, args)
            assert wrap_result.exit_code == 0, "Could not get ECDH wrapper"
            args = "test wrapper ECDH ecdh_wrapper_example.py --resilience --no-save"
            result = runner.invoke(app, args)
            print(result.output)
            assert result.exit_code == 0, "Wrapper failed"


class TestMldsa:
    """Tests ML-DSA wrappers."""

    @pytest.mark.parametrize(("lang", "example"), [("Python", "1")])
    def test_examples(self, lang: str, example: str, tmp_path: Path):
        """Tests ML-DSA examples."""
        with runner.isolated_filesystem(tmp_path):
            wrap_result = runner.invoke(
                app, ["get-wrapper", "MLDSA", "--language", lang, "--example", example]
            )
            assert wrap_result.exit_code == 0, "Could not get ML-DSA wrapper"
            args = [
                "test",
                "wrapper",
                "MLDSA",
                f"MLDSA_wrapper_example_{example}.py",
                "--no-save",
            ]
            result = runner.invoke(app, args)
            print(result.output)
            assert result.exit_code == 0, "Wrapper failed"


class TestMlkem:
    """Tests ML-KEM wrappers."""

    @pytest.mark.parametrize(("lang", "example"), [("Python", "1")])
    def test_examples(self, lang: str, example: str, tmp_path: Path):
        """Tests ML-KEM examples."""
        with runner.isolated_filesystem(tmp_path):
            wrap_result = runner.invoke(
                app, ["get-wrapper", "MLKEM", "--language", lang, "--example", example]
            )
            assert wrap_result.exit_code == 0, "Could not get ML-KEM wrapper"
            args = [
                "test",
                "wrapper",
                "MLKEM",
                f"MLKEM_wrapper_example_{example}.py",
                "--no-save",
            ]
            result = runner.invoke(app, args)
            print(result.output)
            assert result.exit_code == 0, "Wrapper failed"
