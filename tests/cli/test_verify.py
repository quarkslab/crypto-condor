"""Module for testing the verify command."""

import random
import warnings
from pathlib import Path
from typing import Any

import pytest
from Crypto.Cipher import AES as PyAES
from Crypto.Cipher import ChaCha20 as PyChaCha20
from Crypto.Cipher import ChaCha20_Poly1305 as PyChaCha20_Poly1305
from typer.testing import CliRunner

from crypto_condor.cli.main import app
from crypto_condor.constants import SUPPORTED_MODES, Primitive
from crypto_condor.primitives import AES, ECDSA, SHA, ChaCha20
from crypto_condor.vectors.SHA import ShaVectors

runner = CliRunner()

# Use sorted because pytest-xdist requires a deterministic list to compare and
# distribute tasks.
PRIMITIVES_WITH_VERIFY = sorted(
    set([p for p in Primitive if SUPPORTED_MODES[p]["output"]])
)
PRIMITIVES_WITHOUT_VERIFY = sorted(
    set([p for p in Primitive]).difference(PRIMITIVES_WITH_VERIFY)
)


@pytest.mark.parametrize("primitive", PRIMITIVES_WITHOUT_VERIFY)
def test_unsupported_primitives(primitive: str):
    """Tests calling verify on an unsupported primitive."""
    result = runner.invoke(app, ["test", "output", primitive])
    assert result.exit_code != 0
    assert primitive in result.stdout


class TestVerifyAes:
    """Class to group tests of the verify command with AES."""

    @staticmethod
    def generate_verify_data(
        out: Path,
        mode: AES.Mode,
        op: AES.Operation,
        number_tests: int = 1000,
        number_fail: int = 0,
    ):
        """Generates a file of AES test vectors.

        It uses the format expected by :class:`~crypto_condor.primitives.AES.verify`.

        The keys used are randomly generated, with varying lengths (128, 192, and 256
        bits).

        Args:
            out: The path of the output file.
            mode: The AES mode of operation.
            op: The operation being tested.
            number_tests: The number of tests to generate.
            number_fail: The number of tests that should fail.
        """
        data = list()

        # dummy type-hint
        cipher: Any
        pt_size = 64

        def random_key(i: int):
            if i % 3 == 0:
                return random.randbytes(16)
            elif i % 3 == 1:
                return random.randbytes(24)
            else:
                return random.randbytes(32)

        match mode:
            case "ECB":
                for i in range(number_tests):
                    key = random_key(i)
                    pt = random.randbytes(pt_size)
                    cipher = PyAES.new(key, PyAES.MODE_ECB)
                    if i < number_fail:
                        ct = random.randbytes(pt_size)
                    else:
                        ct = cipher.encrypt(pt)
                    if op == AES.Operation.ENCRYPT:
                        line = f"{key.hex()}/{pt.hex()}/{ct.hex()}"
                    else:
                        line = f"{key.hex()}/{ct.hex()}/{pt.hex()}"
                    data.append(line)
            case "CBC":
                for i in range(number_tests):
                    key = random_key(i)
                    pt = random.randbytes(pt_size)
                    iv = random.randbytes(16)
                    cipher = PyAES.new(key, PyAES.MODE_CBC, iv=iv)
                    if i < number_fail:
                        ct = random.randbytes(pt_size)
                    else:
                        ct = cipher.encrypt(pt)
                    if op == AES.Operation.ENCRYPT:
                        line = f"{key.hex()}/{pt.hex()}/{ct.hex()}/{iv.hex()}"
                    else:
                        line = f"{key.hex()}/{ct.hex()}/{pt.hex()}/{iv.hex()}"
                    data.append(line)
            case "CFB8":
                for i in range(number_tests):
                    key = random_key(i)
                    pt = random.randbytes(pt_size)
                    iv = random.randbytes(16)
                    cipher = PyAES.new(key, PyAES.MODE_CFB, iv=iv, segment_size=8)
                    if i < number_fail:
                        ct = random.randbytes(pt_size)
                    else:
                        ct = cipher.encrypt(pt)
                    if op == AES.Operation.ENCRYPT:
                        line = f"{key.hex()}/{pt.hex()}/{ct.hex()}/{iv.hex()}"
                    else:
                        line = f"{key.hex()}/{ct.hex()}/{pt.hex()}/{iv.hex()}"
                    data.append(line)
            case "CFB128" | "CFB":
                for i in range(number_tests):
                    key = random_key(i)
                    pt = random.randbytes(pt_size)
                    iv = random.randbytes(16)
                    cipher = PyAES.new(key, PyAES.MODE_CFB, iv=iv, segment_size=128)
                    if i < number_fail:
                        ct = random.randbytes(pt_size)
                    else:
                        ct = cipher.encrypt(pt)
                    if op == AES.Operation.ENCRYPT:
                        line = f"{key.hex()}/{pt.hex()}/{ct.hex()}/{iv.hex()}"
                    else:
                        line = f"{key.hex()}/{ct.hex()}/{pt.hex()}/{iv.hex()}"
                    data.append(line)
            case "CTR":
                for i in range(number_tests):
                    key = random_key(i)
                    pt = random.randbytes(pt_size)
                    nonce = random.randbytes(12)
                    cipher = PyAES.new(
                        key, PyAES.MODE_CTR, nonce=nonce, initial_value=1
                    )
                    if i < number_fail:
                        ct = random.randbytes(pt_size)
                    else:
                        ct = cipher.encrypt(pt)
                    if op == AES.Operation.ENCRYPT:
                        line = f"{key.hex()}/{pt.hex()}/{ct.hex()}/{nonce.hex()}"
                    else:
                        line = f"{key.hex()}/{ct.hex()}/{pt.hex()}/{nonce.hex()}"
                    data.append(line)
            case "GCM":
                for i in range(number_tests):
                    key = random_key(i)
                    pt = random.randbytes(pt_size)
                    nonce = random.randbytes(12)
                    aad = random.randbytes(32)
                    cipher = PyAES.new(key, PyAES.MODE_GCM, nonce=nonce)
                    cipher.update(aad)
                    ct, tag = cipher.encrypt_and_digest(pt)
                    if i < number_fail:
                        # Change either the ciphertext or the tag.
                        if i % 2:
                            ct = random.randbytes(pt_size)
                        else:
                            tag = random.randbytes(16)
                    if op == AES.Operation.ENCRYPT:
                        line = f"{key.hex()}/{pt.hex()}/{ct.hex()}/{nonce.hex()}/{aad.hex()}/{tag.hex()}"  # noqa: E501
                    else:
                        line = f"{key.hex()}/{ct.hex()}/{pt.hex()}/{nonce.hex()}/{aad.hex()}/{tag.hex()}"  # noqa: E501
                    data.append(line)
            case "CCM":
                for i in range(number_tests):
                    key = random_key(i)
                    pt = random.randbytes(pt_size)
                    nonce = random.randbytes(12)
                    aad = random.randbytes(32)
                    cipher = PyAES.new(key, PyAES.MODE_CCM, nonce=nonce)
                    cipher.update(aad)
                    ct, tag = cipher.encrypt_and_digest(pt)
                    if i < number_fail:
                        if i % 2:
                            ct = random.randbytes(pt_size)
                        else:
                            tag = random.randbytes(16)
                    if op == AES.Operation.ENCRYPT:
                        line = f"{key.hex()}/{pt.hex()}/{ct.hex()}/{nonce.hex()}/{aad.hex()}/{tag.hex()}"  # noqa: E501
                    else:
                        line = f"{key.hex()}/{ct.hex()}/{pt.hex()}/{nonce.hex()}/{aad.hex()}/{tag.hex()}"  # noqa: E501
                    data.append(line)

        text = "\n".join(data)
        with out.open("w") as file:
            file.write(text)

    @pytest.mark.parametrize(
        "mode",
        [
            AES.Mode.ECB,
            AES.Mode.CBC,
            AES.Mode.CFB,
            AES.Mode.CFB8,
            AES.Mode.CFB128,
            AES.Mode.CTR,
            AES.Mode.GCM,
            AES.Mode.CCM,
        ],
    )
    def test_correct_implementation(self, mode: AES.Mode, tmp_path: Path):
        """Tests verifying the output of a correct implementation of AES."""
        src = tmp_path / "verify_ok.txt"
        num_tests = 500
        self.generate_verify_data(src, mode, AES.Operation.ENCRYPT, num_tests)
        enc_result = runner.invoke(
            app,
            [
                "test",
                "output",
                "AES",
                str(src),
                mode,
                AES.Operation.ENCRYPT,
                "--no-save",
            ],
        )
        assert enc_result.exit_code == 0
        assert str(num_tests) in enc_result.output

        self.generate_verify_data(src, mode, AES.Operation.DECRYPT, num_tests)
        dec_result = runner.invoke(
            app,
            [
                "test",
                "output",
                "AES",
                str(src),
                mode,
                AES.Operation.DECRYPT,
                "--no-save",
            ],
        )
        print(dec_result.output)
        assert dec_result.exit_code == 0
        assert str(num_tests) in dec_result.output

    @pytest.mark.parametrize(
        "mode",
        [
            AES.Mode.ECB,
            AES.Mode.CBC,
            AES.Mode.CFB,
            AES.Mode.CFB8,
            AES.Mode.CFB128,
            AES.Mode.CTR,
            AES.Mode.GCM,
            AES.Mode.CCM,
        ],
    )
    def test_faulty_implementation(self, mode: AES.Mode, tmp_path: Path):
        """Tests verifying the output of a faulty implementation of AES."""
        src = tmp_path / "verify_fail.txt"
        num_tests = 500
        num_fail = 142
        self.generate_verify_data(src, mode, AES.Operation.ENCRYPT, num_tests, num_fail)
        enc_result = runner.invoke(
            app,
            [
                "test",
                "output",
                "AES",
                str(src),
                mode,
                AES.Operation.ENCRYPT,
                "--no-save",
            ],
        )
        assert enc_result.exit_code != 0
        assert str(num_fail) in enc_result.stdout

        self.generate_verify_data(src, mode, AES.Operation.DECRYPT, num_tests, num_fail)
        dec_result = runner.invoke(
            app,
            [
                "test",
                "output",
                "AES",
                str(src),
                mode,
                AES.Operation.DECRYPT,
                "--no-save",
            ],
        )
        print(dec_result.output)
        assert dec_result.exit_code != 0
        assert str(num_fail) in dec_result.output


class TestEcdsa:
    """Class to group tests of the verify command with ECDSA."""

    @staticmethod
    def format_wycheproof(
        curve: ECDSA.Curve,
        hash_function: ECDSA.Hash,
        out: Path,
        valid: bool,
    ) -> int:
        """Formats Wycheproof test vectors for testing.

        It uses the format expected by
        :class:`~crypto_condor.primitives.ECDSA.verify_file`.

        Args:
            curve:
                The elliptic curve to use.
            hash_function:
                The hash function to use.
            out:
                The file to which the formatted data is written to.
            valid:
                If True, only valid tests are used. Otherwise only invalid tests are
                used.

        Returns:
            The number of tests written.

        Note:
            It currently skips "acceptable" tests.
        """
        vectors = ECDSA.EcdsaSigVerVectors.load(curve, hash_function, compliance=False)
        if vectors.wycheproof is None:
            return 0

        selected_vectors = list()

        for test_group in vectors.wycheproof["testGroups"]:
            key = test_group["keyDer"]
            for test in test_group["tests"]:
                if test["result"] == "acceptable":
                    continue
                if valid and test["result"] == "invalid":
                    continue
                if not valid and test["result"] == "valid":
                    continue
                message = test["msg"]
                signature = test["sig"]
                selected_vectors.append(f"{key}/{message}/{signature}")

        text = "\n".join(selected_vectors)
        try:
            with out.open("w") as file:
                file.write(text)
        except IOError:
            return 0

        return len(selected_vectors)

    # TODO: add parameters
    @pytest.mark.parametrize(
        "curve,hash_function",
        [
            (ECDSA.Curve.SECP192R1, ECDSA.Hash.SHA_256),
            (ECDSA.Curve.SECP256R1, ECDSA.Hash.SHA_256),
        ],
    )
    def test_correct_implementation(
        self, curve: ECDSA.Curve, hash_function: ECDSA.Hash, tmp_path: Path
    ):
        """Tests the output of a correct implementation of ECDSA."""
        out = tmp_path / "verify_ok.txt"
        number_tests = self.format_wycheproof(curve, hash_function, out, True)
        assert number_tests > 0, "Verify data was not generated"

        result = runner.invoke(
            app,
            [
                "test",
                "output",
                "ECDSA",
                str(out),
                "DER",
                str(hash_function),
                "--no-save",
            ],
        )
        print(result.output)
        assert result.exit_code == 0
        assert str(number_tests) in result.stdout

    # TODO: add parameters
    @pytest.mark.parametrize(
        "curve,hash_function",
        [
            (ECDSA.Curve.SECP192R1, ECDSA.Hash.SHA_256),
            (ECDSA.Curve.SECP256R1, ECDSA.Hash.SHA_256),
        ],
    )
    def test_faulty_implementation(
        self, curve: ECDSA.Curve, hash_function: ECDSA.Hash, tmp_path: Path
    ):
        """Tests the output of a faulty implementation of ECDSA."""
        out = tmp_path / "verify_fail.txt"
        number_tests = self.format_wycheproof(curve, hash_function, out, False)
        assert number_tests > 0, "Verify data was not generated"

        result = runner.invoke(
            app,
            [
                "test",
                "output",
                "ECDSA",
                str(out),
                "DER",
                str(hash_function),
                "--no-save",
            ],
        )
        assert result.exit_code != 0
        assert str(number_tests) in result.stdout


class TestSha:
    """Class to group test of the 'verify SHA' subcommand."""

    @staticmethod
    def generate_data(algo: SHA.Algorithm, out: Path, *, failed: int = 0) -> int:
        """Generates data to verify from SHA vectors.

        Args:
            algo:
                The hash algorithm to generate data for.
            out:
                The file to write the data to.

        Keyword Args:
            failed:
                The number of invalid tests to include.

        Returns:
            The number of tests written.
        """
        data = list()

        try:
            vectors = ShaVectors.load(algo, SHA.Orientation.BYTE)
        except ValueError:
            raise

        for vector in vectors.short_msg.tests:
            if failed > 0:
                digest = SHA._sha(algo, random.randbytes(256)).hex()
            else:
                digest = vector.md.hex()
            data.append(f"{vector.msg.hex()}/{digest}")
        for vector in vectors.long_msg.tests:
            if failed > 0:
                digest = SHA._sha(algo, random.randbytes(256)).hex()
            else:
                digest = vector.md.hex()
            data.append(f"{vector.msg.hex()}/{digest}")

        out.write_text("\n".join(data))
        return len(data)

    @pytest.mark.parametrize("algorithm", SHA.Algorithm)
    def test_correct_implementation(self, algorithm: SHA.Algorithm, tmp_path: Path):
        """Tests the `verify SHA` command."""
        src = tmp_path / f"{str(algorithm).replace('/', '_')}_ok.txt"
        try:
            num_tests = self.generate_data(algorithm, src)
        except ValueError:
            warnings.warn(
                f"Could not generate input data for {str(algorithm)} test", stacklevel=0
            )
            return

        print(num_tests)
        result = runner.invoke(
            app, ["test", "output", "SHA", str(src), str(algorithm), "--no-save"]
        )
        print(result.stdout)
        assert result.exit_code == 0


class TestChaCha:
    """Tests `test output chacha`."""

    @staticmethod
    def generate_data(
        out: Path,
        mode: ChaCha20.Mode,
        op: ChaCha20.Operation,
        number_tests: int = 1000,
        number_fail: int = 0,
    ):
        """Generates a file of ChaCha20(-Poly1305) test vectors.

        The file conforms to the expected format for
        :func:`crypto_condor.primitives.ChaCha20.verify`.

        The nonces generated are 12 bytes long.

        Args:
            out: The path of the output file.
            mode: The ChaCha20 mode of operation.
            op: The operation to test.
            number_tests: The number of test vectors to generate.
            number_fail: The number of generated test vectors that should fail, can't be
                greater than :attr:`number_tests`.
        """
        lines = list()
        mid = (number_tests + number_fail) // 2

        for i in range(number_tests):
            key = random.randbytes(32)
            pt = random.randbytes(64)
            nonce = random.randbytes(12)

            match (mode, op):
                case (ChaCha20.Mode.CHACHA20, ChaCha20.Operation.ENCRYPT):
                    if i < number_fail:
                        ct = random.randbytes(64)
                    else:
                        ct = PyChaCha20.new(key=key, nonce=nonce).encrypt(pt)
                    # Create half of valid tests with init_counter and half without.
                    if i < number_fail + mid:
                        line = f"{key.hex()}/{pt.hex()}/{ct.hex()}/{nonce.hex()}/0"
                    else:
                        line = f"{key.hex()}/{pt.hex()}/{ct.hex()}/{nonce.hex()}"
                case (ChaCha20.Mode.CHACHA20, ChaCha20.Operation.DECRYPT):
                    ct = PyChaCha20.new(key=key, nonce=nonce).encrypt(pt)
                    if i < number_fail:
                        pt = random.randbytes(64)
                    # Create half of valid tests with init_counter and half without.
                    if i < number_fail + mid:
                        line = f"{key.hex()}/{ct.hex()}/{pt.hex()}/{nonce.hex()}/0"
                    else:
                        line = f"{key.hex()}/{ct.hex()}/{pt.hex()}/{nonce.hex()}"
                case (ChaCha20.Mode.CHACHA20_POLY1305, ChaCha20.Operation.ENCRYPT):
                    if i < number_fail:
                        ct, mac = random.randbytes(64), random.randbytes(16)
                        aad = random.randbytes(16)
                    else:
                        cipher = PyChaCha20_Poly1305.new(key=key, nonce=nonce)
                        # Create half of valid tests with aad and half without.
                        if i < number_fail + mid:
                            aad = b"crypto-condor" + random.randbytes(8)
                            cipher.update(aad)
                        ct, mac = cipher.encrypt_and_digest(pt)
                    if i < number_fail + mid:
                        line = f"{key.hex()}/{pt.hex()}/{ct.hex()}/{nonce.hex()}/{mac.hex()}/{aad.hex()}"  # noqa: E501
                    else:
                        line = f"{key.hex()}/{pt.hex()}/{ct.hex()}/{nonce.hex()}/{mac.hex()}"  # noqa: E501
                case (ChaCha20.Mode.CHACHA20_POLY1305, ChaCha20.Operation.DECRYPT):
                    cipher = PyChaCha20_Poly1305.new(key=key, nonce=nonce)
                    # Create half of valid tests with aad and half without.
                    if i < number_fail + mid:
                        aad = b"crypto-condor" + random.randbytes(8)
                        cipher.update(aad)
                    ct, mac = cipher.encrypt_and_digest(pt)
                    if i < number_fail:
                        pt = random.randbytes(64)
                    if i < number_fail + mid:
                        line = f"{key.hex()}/{ct.hex()}/{pt.hex()}/{nonce.hex()}/{mac.hex()}/{aad.hex()}"  # noqa: E501
                    else:
                        line = f"{key.hex()}/{ct.hex()}/{pt.hex()}/{nonce.hex()}/{mac.hex()}"  # noqa: E501
                case _:
                    raise ValueError("Unknown ChaCha20 mode of operation %s" % mode)
            lines.append(line)

        text = "\n".join(lines)
        with out.open("w") as file:
            file.write(text)

    @pytest.mark.parametrize("mode", ChaCha20.Mode)
    def test_correct_implementation(self, mode: ChaCha20.Mode, tmp_path: Path):
        """Tests :func:`ChaCha20.verify` with the output of a correct implementation."""
        file = tmp_path / f"{str(mode)}_verify_correct.txt"
        number_tests = 1000
        self.generate_data(file, mode, ChaCha20.Operation.ENCRYPT, number_tests)

        enc_result = runner.invoke(
            app,
            [
                "test",
                "output",
                "ChaCha20",
                str(file),
                str(mode),
                "encrypt",
                "--no-save",
            ],
        )
        assert enc_result.exit_code == 0, enc_result.output
        assert str(number_tests) in enc_result.output

        self.generate_data(file, mode, ChaCha20.Operation.DECRYPT, number_tests)
        dec_result = runner.invoke(
            app,
            [
                "test",
                "output",
                "ChaCha20",
                str(file),
                str(mode),
                "decrypt",
                "--no-save",
            ],
        )
        assert dec_result.exit_code == 0, dec_result.output
        assert str(number_tests) in dec_result.output

    @pytest.mark.parametrize("mode", ChaCha20.Mode)
    def test_flawed_implementation(self, mode: ChaCha20.Mode, tmp_path: Path):
        """Tests :func:`ChaCha20.verify` with the output of a flawed implementation."""
        file = tmp_path / f"{str(mode)}_verify_correct.txt"
        number_tests = 1000
        number_fail = 242
        self.generate_data(
            file,
            mode,
            ChaCha20.Operation.ENCRYPT,
            number_tests,
            number_fail=number_fail,
        )

        enc_result = runner.invoke(
            app,
            [
                "test",
                "output",
                "ChaCha20",
                str(file),
                str(mode),
                "encrypt",
                "--no-save",
            ],
        )
        assert enc_result.exit_code == 1, enc_result.output
        assert str(number_fail) in enc_result.output, enc_result.output

        self.generate_data(
            file,
            mode,
            ChaCha20.Operation.DECRYPT,
            number_tests,
            number_fail=number_fail,
        )
        dec_result = runner.invoke(
            app,
            [
                "test",
                "output",
                "ChaCha20",
                str(file),
                str(mode),
                "decrypt",
                "--no-save",
            ],
        )
        assert dec_result.exit_code == 1, dec_result.output
        assert str(number_fail) in dec_result.output, dec_result.output
