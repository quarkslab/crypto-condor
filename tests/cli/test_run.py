"""Module for testing the 'run' command."""

import warnings
from pathlib import Path

import pytest
from typer.testing import CliRunner

from crypto_condor.cli.main import app
from crypto_condor.constants import SUPPORTED_MODES, Primitive
from crypto_condor.primitives import ECDSA

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

    @pytest.mark.skip(reason="PyCryptodome fails some tests")
    @pytest.mark.parametrize(
        "curve,hash_function",
        [
            pytest.param(
                ECDSA.Curve.SECP256R1,
                ECDSA.Hash.SHA_256,
                marks=pytest.mark.xfail(reason="PyCryptodome fails 1 Wycheproof test"),
            ),
            pytest.param(
                ECDSA.Curve.SECP192R1,
                ECDSA.Hash.SHA_256,
                marks=pytest.mark.xfail(reason="PyCryptodome fails 1 Wycheproof test"),
            ),
            pytest.param(
                ECDSA.Curve.SECP224R1,
                ECDSA.Hash.SHA_256,
                marks=pytest.mark.xfail(reason="PyCryptodome fails 1 Wycheproof test"),
            ),
            pytest.param(
                ECDSA.Curve.SECP384R1,
                ECDSA.Hash.SHA_256,
            ),
        ],
    )
    def test_pycryptodome_example(
        self,
        curve: ECDSA.Curve,
        hash_function: ECDSA.Hash,
        tmp_path: Path,
    ):
        """Tests the ECDSA PyCryptodome wrapper examples."""
        with runner.isolated_filesystem(tmp_path):
            result = runner.invoke(
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
            if result.exit_code != 0:
                warnings.warn("Could not get wrapper example", stacklevel=0)
                return

            args = [
                "test",
                "wrapper",
                "ECDSA",
                "-l",
                "python",
                "--curve",
                str(curve),
                "--hash",
                str(hash_function),
                "--key-encoding",
                ECDSA.KeyEncoding.DER,
                "--pubkey-encoding",
                ECDSA.PubKeyEncoding.DER,
                "--no-save",
            ]

            result = runner.invoke(app, args)
            print(result.output)
            assert "large x-coordinate" in result.output
            assert result.exit_code == 0

    @pytest.mark.parametrize(
        "curve,hash_function",
        [
            (ECDSA.Curve.SECP192R1, ECDSA.Hash.SHA_256),
            (ECDSA.Curve.SECP224R1, ECDSA.Hash.SHA_256),
            (ECDSA.Curve.SECP256R1, ECDSA.Hash.SHA_256),
            (ECDSA.Curve.SECP256K1, ECDSA.Hash.SHA_256),
            (ECDSA.Curve.SECP384R1, ECDSA.Hash.SHA_256),
            (ECDSA.Curve.BRAINPOOLP256R1, ECDSA.Hash.SHA_256),
        ],
    )
    def test_cryptography_example(
        self,
        curve: ECDSA.Curve,
        hash_function: ECDSA.Hash,
    ):
        """Tests the ECDSA cryptography wrapper examples."""
        with runner.isolated_filesystem():
            wrap_result = runner.invoke(
                app,
                [
                    "get-wrapper",
                    "ECDSA",
                    "--language",
                    ECDSA.Wrapper.PYTHON,
                    "--example",
                    "2",
                    "--force",
                ],
            )
            assert wrap_result.exit_code == 0, "Could not get wrapper"

            args = [
                "test",
                "wrapper",
                "ECDSA",
                ECDSA.Wrapper.PYTHON,
                curve,
                hash_function,
                "--key-encoding",
                ECDSA.KeyEncoding.DER,
                "--pubkey-encoding",
                ECDSA.PubKeyEncoding.DER,
                "--no-save",
            ]

            result = runner.invoke(app, args)
            print(result.output)
            assert result.exit_code == 0

    @pytest.mark.parametrize(
        "curve,hash_function",
        [
            (ECDSA.Curve.SECP192R1, ECDSA.Hash.SHA_256),
            (ECDSA.Curve.SECP224R1, ECDSA.Hash.SHA_256),
            (ECDSA.Curve.SECP256R1, ECDSA.Hash.SHA_256),
            (ECDSA.Curve.SECP256K1, ECDSA.Hash.SHA_256),
            (ECDSA.Curve.SECP384R1, ECDSA.Hash.SHA_256),
            (ECDSA.Curve.BRAINPOOLP256R1, ECDSA.Hash.SHA_256),
        ],
    )
    def test_cryptography_example_sign_then_verify(
        self,
        curve: ECDSA.Curve,
        hash_function: ECDSA.Hash,
    ):
        """Tests the sign-then-verify using the cryptography wrapper."""
        with runner.isolated_filesystem():
            wrap_result = runner.invoke(
                app,
                [
                    "get-wrapper",
                    "ECDSA",
                    "--language",
                    ECDSA.Wrapper.PYTHON,
                    "--example",
                    "2",
                    "--force",
                ],
            )
            if wrap_result.exit_code != 0:
                warnings.warn("Could not get wrapper example", stacklevel=0)
                return

            args = [
                "test",
                "wrapper",
                "ECDSA",
                ECDSA.Wrapper.PYTHON,
                curve,
                hash_function,
                "--no-sign",
                "--no-verify",
                "--sign-then-verify",
                "--key-encoding",
                ECDSA.KeyEncoding.DER,
                "--pubkey-encoding",
                ECDSA.PubKeyEncoding.DER,
                "--no-save",
            ]

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

    @pytest.mark.parametrize(
        "example,scheme,sha,mgf_sha",
        [
            ("1", "RSASSA-PKCS1-v1_5", "SHA-256", None),
            ("2", "RSASSA-PSS", "SHA-256", "SHA-256"),
        ],
    )
    def test_rsa_examples(
        self, example: str, scheme: str, sha: str, mgf_sha: str | None
    ):
        """Tests the RSA wrapper examples."""
        with runner.isolated_filesystem():
            wrap_result = runner.invoke(
                app,
                [
                    "get-wrapper",
                    "RSASSA",
                    "--language",
                    "Python",
                    "--example",
                    example,
                    "--force",
                ],
            )
            assert wrap_result.exit_code == 0, "Could not get wrapper example"
            args = ["test", "wrapper", "RSASSA", "Python", scheme, sha, "--no-save"]
            if mgf_sha is not None:
                args += ["--mgf-sha", mgf_sha]
            result = runner.invoke(app, args)
            print(result.output)
            assert result.exit_code == 0


class TestRSAES:
    """Test RSAES wrappers."""

    @pytest.mark.parametrize(
        "example,scheme,sha,mgf_sha",
        [
            ("1", "RSAES-PKCS1-v1_5", "SHA-256", None),
            ("2", "RSAES-OAEP", "SHA-256", "SHA-256"),
            ("3", "RSAES-OAEP", "SHA-256", "SHA-1"),
        ],
    )
    def test_examples(self, example: str, scheme: str, sha: str, mgf_sha: str | None):
        """Tests the RSAES wrapper examples."""
        with runner.isolated_filesystem():
            wrap_result = runner.invoke(
                app,
                [
                    "get-wrapper",
                    "RSAES",
                    "--language",
                    "Python",
                    "--example",
                    example,
                    "--force",
                ],
            )
            if wrap_result.exit_code != 0:
                warnings.warn("Could not get wrapper example", stacklevel=0)
                return

            args = [
                "test",
                "wrapper",
                "RSAES",
                "Python",
                scheme,
                "--sha",
                sha,
                "--no-save",
            ]

            if mgf_sha is not None:
                args += ["--mgf-sha", mgf_sha]

            result = runner.invoke(app, args)
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
