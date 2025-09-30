"""The ChaCha20 module."""

import importlib
import inspect
import json
import logging
import sys
from importlib import resources
from pathlib import Path
from typing import Protocol

import attrs
import cffi
import strenum
from Crypto.Cipher import ChaCha20, ChaCha20_Poly1305
from rich.progress import track

from crypto_condor.primitives.common import Results, ResultsDict, TestInfo, TestType
from crypto_condor.vectors._chacha20.chacha20_pb2 import Chacha20Test, Chacha20Vectors
from crypto_condor.vectors.chacha20 import Mode

logger = logging.getLogger(__name__)


def __dir__():  # pragma: no cover
    return [
        # Enums
        Operation.__name__,
        Wrapper.__name__,
        # Protocols
        Encrypt.__name__,
        Decrypt.__name__,
        EncryptPoly.__name__,
        DecryptPoly.__name__,
        # Dataclasses
        # Test functions
        test_encrypt.__name__,
        test_encrypt_poly.__name__,
        test_decrypt.__name__,
        test_decrypt_poly.__name__,
        # Test output
        test_output_encrypt.__name__,
        test_output_decrypt.__name__,
        test_output_encrypt_poly.__name__,
        test_output_decrypt_poly.__name__,
        # Harnesses
        test_lib.__name__,
        test_harness_python.__name__,
        # Imported
        Mode.__name__,
    ]


# -------------------------------------------------------------------------------------
# Enums
# -------------------------------------------------------------------------------------


class Operation(strenum.StrEnum):
    """Supported operations."""

    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"


class Wrapper(strenum.StrEnum):
    """Supported wrapper languages."""

    PYTHON = "Python"


# -------------------------------------------------------------------------------------
# Protocols
# -------------------------------------------------------------------------------------


class Encrypt(Protocol):
    """Represents a function that encrypts with ChaCha20."""

    def __call__(
        self, key: bytes, pt: bytes, nonce: bytes, init_counter: int = 0
    ) -> bytes:
        """Encrypts with ChaCha20.

        Args:
            key:
                The symmetric key.
            pt:
                The plaintext to encrypt.
            nonce:
                The nonce.
            init_counter:
                A position to seek in the keystream before encrypting, in bytes.

        Returns:
            The ciphertext.
        """
        ...


class Decrypt(Protocol):
    """Represents a function that decrypts with ChaCha20."""

    def __call__(
        self, key: bytes, ct: bytes, nonce: bytes, init_counter: int = 0
    ) -> bytes:
        """Decrypts with ChaCha20.

        Args:
            key:
                The symmetric key.
            ct:
                The ciphertext to decrypt.
            nonce:
                The nonce.

        Keyword Args:
            init_counter:
                A position to seek in the keystream before encrypting, in bytes.

        Returns:
            The plaintext.
        """
        ...


class EncryptPoly(Protocol):
    """Represents a function that encrypts with ChaCha20-Poly1305."""

    def __call__(
        self, key: bytes, pt: bytes, nonce: bytes, aad: bytes
    ) -> tuple[bytes, bytes]:
        """Encrypts with ChaCha20-Poly1305.

        Args:
            key:
                The symmetric key.
            pt:
                The plaintext to encrypt.
            nonce:
                The nonce.
            aad:
                The associated data.

        Returns:
            A tuple containing the ciphertext and the MAC tag.

        Raises:
            ValueError:
                If an input is incorrect (e.g. the nonce size is invalid).
        """
        ...


class DecryptPoly(Protocol):
    """Represents a function that decrypts with ChaCha20-Poly1305."""

    def __call__(
        self, key: bytes, ct: bytes, nonce: bytes, tag: bytes, aad: bytes
    ) -> bytes | None:
        """Decrypts with ChaCha20-Poly1305.

        Args:
            key:
                The symmetric key.
            ct:
                The ciphertext to decrypt.
            nonce:
                The 12-byte nonce.
            tag:
                The MAC tag.
            aad:
                The associated data.

        Returns:
            The decrypted plaintext.

        Raises:
            ValueError:
                If an input is incorrect (e.g. the nonce size is not 12 bytes) or if the
                MAC verification failed.
        """
        ...


# -------------------------------------------------------------------------------------
# Dataclasses
# -------------------------------------------------------------------------------------


@attrs.define
class EncData:
    """Debug data for :func:`test_encrypt`.

    Args:
        key: The symmetric key.
        pt: The plaintext.
        ct: The ciphertext.
        nonce: The nonce.
        counter: The initial counter.

    Keyword Args:
        ret_ct: The ciphertext returned by the implementation.
    """

    key: bytes
    nonce: bytes
    pt: bytes
    ct: bytes
    counter: int
    ret_ct: bytes | None = None

    @classmethod
    def from_test(cls, test: Chacha20Test):
        """Creates a new instance from a test."""
        return cls(test.key, test.nonce, test.pt, test.ct, test.counter)

    def __str__(self) -> str:
        """Returns a string representation."""
        return f"""key = {self.key.hex()}
nonce = {self.nonce.hex()}
pt = {self.pt.hex()}
counter = {self.counter}
ct = {self.ct.hex()}
returned ct = {self.ret_ct.hex() if self.ret_ct is not None else "<none>"}
"""


@attrs.define
class EncPolyData:
    """Debug data for :func:`test_encrypt_poly`.

    Args:
        key: The symmetric key.
        nonce: The nonce.
        pt: The plaintext.
        ct: The expected ciphertext.
        aad: The associated data.
        tag: The expected MAC tag.

    Keyword Args:
        ret_ct: The returned ciphertext.
        ret_tag: The returned MAC tag.
    """

    key: bytes
    nonce: bytes
    pt: bytes
    ct: bytes
    aad: bytes
    tag: bytes
    ret_ct: bytes | None = None
    ret_tag: bytes | None = None

    @classmethod
    def from_test(cls, test: Chacha20Test):
        """Creates a new instance from a test."""
        return cls(test.key, test.nonce, test.pt, test.ct, test.aad, test.tag)

    def __str__(self) -> str:
        """Returns a string representation."""
        return f"""key = {self.key.hex()}
nonce = {self.nonce.hex()}
pt = {self.pt.hex()}
aad = {self.aad.hex() if self.aad else "<none>"}
ct = {self.ct.hex()}
tag = {self.tag.hex()}
returned ct = {self.ret_ct.hex() if self.ret_ct is not None else "<none>"}
returned tag = {self.ret_tag.hex() if self.ret_tag is not None else "<none>"}
"""


@attrs.define
class DecData:
    """Debug data for :func:`test_decrypt`.

    Args:
        key: The symmetric key.
        ct: The ciphertext.
        pt: The plaintext.
        nonce: The nonce.
        counter: The initial counter.

    Keyword Args:
        ret_pt: The plaintext returned by the implementation.
    """

    key: bytes
    ct: bytes
    pt: bytes
    nonce: bytes
    counter: int
    ret_pt: bytes | None = None

    @classmethod
    def from_test(cls, test: Chacha20Test):
        """Creates a new instance from a test."""
        return cls(test.key, test.ct, test.pt, test.nonce, test.counter)

    def __str__(self) -> str:
        """Returns a string representation."""
        return f"""key = {self.key.hex()}
ct = {self.ct.hex()}
pt = {self.pt.hex()}
nonce = {self.nonce.hex()}
counter = {self.counter}
returned pt = {self.ret_pt.hex() if self.ret_pt is not None else "<none>"}
"""

@attrs.define
class DecPolyData:
    """Debug data for :func:`test_decrypt_poly`.

    Args:
        key: The symmetric key.
        ct: The ciphertext.
        pt: The plaintext.
        nonce: The nonce.
        tag: The MAC tag.
        aad: The associated data.

    Keyword Args:
        ret_pt: The plaintext returned by the implementation.
    """

    key: bytes
    ct: bytes
    pt: bytes
    nonce: bytes
    tag: bytes
    aad: bytes
    ret_pt: bytes | None = None

    @classmethod
    def from_test(cls, test: Chacha20Test):
        """Creates a new instance from a test."""
        return cls(test.key, test.ct, test.pt, test.nonce, test.tag, test.aad)

    def __str__(self) -> str:
        """Returns a string representation."""
        return f"""key = {self.key.hex()}
ct = {self.ct.hex()}
pt = {self.pt.hex()}
nonce = {self.nonce.hex()}
tag = {self.tag.hex()}
aad = {self.aad.hex()}
returned pt = {self.ret_pt.hex() if self.ret_pt is not None else "<none>"}
"""

# -------------------------------------------------------------------------------------
# Internal functions
# -------------------------------------------------------------------------------------


def _load_vectors(
    mode: Mode, compliance: bool, resilience: bool
) -> list[Chacha20Vectors]:
    """Loads vectors for a given mode and key length.

    Returns:
        A list of vectors.
    """
    vectors_dir = resources.files("crypto_condor") / "vectors/_chacha20"
    vectors = list()

    sources_file = vectors_dir / "chacha20.json"
    with sources_file.open("r") as file:
        sources = json.load(file)

    for filename in sources[mode]:
        vectors_file = vectors_dir / "pb2" / filename
        _vec = Chacha20Vectors()
        logger.debug("Loading ChaCha20 vectors from %s", str(filename))
        try:
            _vec.ParseFromString(vectors_file.read_bytes())
        except Exception:
            logger.exception("Failed to load ChaCha20 vectors from %s", str(filename))
            continue
        if _vec.compliance and compliance:
            vectors.append(_vec)
        if not _vec.compliance and resilience:
            vectors.append(_vec)

    if not vectors:
        logger.error(
            "No ChaCha20 test vectors for mode=%s, compliance=%s, resilience=%s",
            str(mode),
            compliance,
            resilience,
        )

    return vectors


def _encrypt(key: bytes, pt: bytes, nonce: bytes, init_counter: int = 0) -> bytes:
    cipher = ChaCha20.new(key=key, nonce=nonce)
    if init_counter:
        cipher.seek(64 * init_counter)
    return cipher.encrypt(pt)


def _encrypt_poly(key: bytes, pt: bytes, nonce: bytes, aad: bytes | None):
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    if aad is not None:
        cipher.update(aad)
    return cipher.encrypt_and_digest(pt)


def _decrypt(key: bytes, ct: bytes, nonce: bytes, init_counter: int = 0) -> bytes:
    cipher = ChaCha20.new(key=key, nonce=nonce)
    if init_counter > 0:
        cipher.seek(64 * init_counter)
    return cipher.decrypt(ct)


def _decrypt_poly(
    key: bytes, ct: bytes, nonce: bytes, tag: bytes, aad: bytes | None
) -> bytes | None:
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    if aad is not None:
        cipher.update(aad)
    try:
        pt = cipher.decrypt_and_verify(ct, tag)
    except ValueError:
        return None
    else:
        return pt


# -------------------------------------------------------------------------------------
# Tests
# -------------------------------------------------------------------------------------


def test_encrypt(encrypt: Encrypt, compliance: bool, resilience: bool) -> ResultsDict:
    """Tests a function that encrypts with ChaCha20.

    Calls `encrypt` to encrypt messages with valid keys and nonces. The test passes if
    all resulting ciphertexts match the test vectors'.

    Args:
        encrypt:
            The function to test.
        compliance:
            Whether to use compliance test vectors.
        resilience:
            Whether to use resilience test vectors.

    Returns:
        A dictionary of results, with a single :class:`Results` per test vectors file.
    """
    rd = ResultsDict()
    test_vectors = _load_vectors(Mode.CHACHA20, compliance, resilience)
    if not test_vectors:
        return rd

    test: Chacha20Test
    for vectors in test_vectors:
        res = Results.new("Test ChaCha20 encryption", [])
        rd.add(res, extra_values=[vectors.source])

        for test in track(
            vectors.tests, rf"\[ChaCha20]\[{vectors.source}] Test encryption"
        ):
            data = EncData.from_test(test)
            info = TestInfo.new_from_test(test, vectors.compliance, data)

            try:
                data.ret_ct = encrypt(test.key, test.pt, test.nonce, test.counter)
            except NotImplementedError:
                logger.warning("ChaCha20 encrypt not implemented, test skipped")
                return rd
            except Exception as error:
                info.fail(f"Exception caught: {str(error)}")
                res.add(info)
                continue

            match (test.type, data.ret_ct == data.ct):
                case (TestType.VALID, True):
                    info.ok()
                case (TestType.VALID, False):
                    info.fail("Wrong ciphertext")
                case _:
                    # Currently we only have valid test vectors.
                    raise ValueError(f"Invalid test type {test.type}")
            res.add(info)

    return rd


def test_encrypt_poly(
    encrypt: EncryptPoly, compliance: bool, resilience: bool
) -> ResultsDict:
    """Tests a function that encrypts with ChaCha20-Poly1305.

    Calls `encrypt` to encrypt messages. The resulting ciphertext and tag are compared
    to those in the test vectors. The test passes if all values match.

    Implementations must follow :protocol:`EncryptPoly` and are expected to check that
    the inputs, notably the nonce, are the correct size, or raise ValueError if not. All
    other exceptions are marked as failures.

    Args:
        encrypt:
            The function to test.
        compliance:
            Whether to use compliance test vectors.
        resilience:
            Whether to use resilience test vectors.

    Returns:
        A dictionary of results, with a single :class:`Results` per test vectors file.
    """
    rd = ResultsDict()
    test_vectors = _load_vectors(Mode.CHACHA20_POLY1305, compliance, resilience)
    if not test_vectors:
        return rd

    test: Chacha20Test
    for vectors in test_vectors:
        res = Results.new("Test ChaCha20-Poly1305 encryption", [])
        rd.add(res, extra_values=[vectors.source])

        for test in track(
            vectors.tests, rf"\[ChaPoly]\[{vectors.source}] Test encryption"
        ):
            # TODO: testing some flags out, it would be better to create two sets of
            # test vectors that can be used with encrypt/decrypt/both.
            # NOTE: ModifiedTag ignored since the other inputs are correct but the tag
            # cannot be compared -- this is a test for decryption.
            if "ModifiedTag" in test.flags:
                continue

            data = EncPolyData.from_test(test)
            info = TestInfo.new_from_test(test, vectors.compliance, data)

            try:
                ret_value = encrypt(test.key, test.pt, test.nonce, test.aad)
            except NotImplementedError:
                logger.warning(
                    "ChaCha20-Poly1305 encrypt not implemented, test skipped"
                )
                return rd
            except ValueError as error:
                if "InvalidNonceSize" in test.flags:
                    # TODO: we assume that ValueError was raised due to the invalid
                    # nonce size without checking if it's really the case.
                    info.ok()
                else:
                    info.fail(f"Caught ValueError: {str(error)}")
                res.add(info)
                continue
            except Exception as error:
                info.fail(f"Exception caught: {str(error)}")
                res.add(info)
                continue

            try:
                data.ret_ct, data.ret_tag = ret_value
            except ValueError:
                info.fail("Wrong return value, expected tuple with two values")
                res.add(info)
                continue

            same_ct = data.ct == data.ret_ct
            same_tag = data.tag == data.ret_tag

            match (test.type, same_ct, same_tag):
                case (TestType.VALID, True, True):
                    info.ok()
                case (TestType.VALID, False, True):
                    info.fail("Wrong ciphertext")
                case (TestType.VALID, True, False):
                    info.fail("Wrong tag")
                case (TestType.VALID, False, False):
                    info.fail("Wrong ciphertext and tag")
                case (TestType.INVALID, *_):
                    # NOTE: assuming that all invalid test vectors should raise an error
                    # (currently only InvalidNonceSize), the function should raise
                    # ValueError and be caught before reaching this match.
                    info.fail("Invalid test did not raise error")
                case _:
                    # NOTE: no acceptable test vectors for now.
                    raise ValueError(
                        f"Invalid test type {test.type} and result {same_ct}"
                    )
            res.add(info)

    return rd


def test_decrypt(decrypt: Decrypt, compliance: bool, resilience: bool) -> ResultsDict:
    """Tests a function that decrypts with ChaCha20.

    Calls `decrypt` to decrypt ciphertexts with valid keys and nonces. The test passes
    if all messages are correctly decrypted.

    Args:
        decrypt:
            The function to test.
        compliance:
            Whether to use compliance test vectors.
        resilience:
            Whether to use resilience test vectors.

    Returns:
        A dictionary of results, with a single :class:`Results` per test vectors file.
    """
    rd = ResultsDict()
    test_vectors = _load_vectors(Mode.CHACHA20, compliance, resilience)
    if not test_vectors:
        return rd

    test: Chacha20Test
    for vectors in test_vectors:
        res = Results.new("Test ChaCha20 decryption", [])
        rd.add(res, extra_values=[vectors.source])

        for test in track(
            vectors.tests, rf"\[ChaCha20]\[{vectors.source}] Test decryption"
        ):
            data = DecData.from_test(test)
            info = TestInfo.new_from_test(test, vectors.compliance, data)

            try:
                data.ret_pt = decrypt(test.key, test.ct, test.nonce, test.counter)
            except NotImplementedError:
                logger.warning("ChaCha20 decrypt not implemented, test stopped")
                return rd
            except Exception as error:
                info.fail(f"Exception caught: {str(error)}", data)
                res.add(info)
                continue

            match (test.type, data.pt == data.ret_pt):
                case (TestType.VALID, True):
                    info.ok()
                case (TestType.VALID, False):
                    info.fail("Wrong ciphertext")
                case _:
                    # NOTE: no other types of test vectors for now.
                    raise ValueError(f"Invalid test type {test.type}")
            res.add(info)

    return rd


def test_decrypt_poly(
    decrypt: DecryptPoly, compliance: bool, resilience: bool
) -> ResultsDict:
    """Tests a function that decrypts with ChaCha20-Poly1305.

    Calls `decrypt` to decrypt ciphertexts with their authentication tags. Resilience
    test vectors contain invalid values: both invalid nonces and invalid tags.
    Implementations must follow :protocol:`DecryptPoly` and raise ValueError if needed.
    The test passes if all valid ciphertexts are correctly decrypted, and all invalid
    tests are rejected.

    Args:
        decrypt:
            The function to test.
        compliance:
            Whether to use compliance test vectors.
        resilience:
            Whether to use resilience test vectors.

    Returns:
        A dictionary of results, with a single :class:`Results` per test vectors file.
    """
    rd = ResultsDict()
    test_vectors = _load_vectors(Mode.CHACHA20_POLY1305, compliance, resilience)
    if not test_vectors:
        return rd

    test: Chacha20Test
    for vectors in test_vectors:
        res = Results.new("Test ChaCha20-Poly1305 decryption", [])
        rd.add(res, extra_values=[vectors.source])

        for test in track(
            vectors.tests, rf"\[ChaPoly]\[{vectors.source}] Test decryption"
        ):
            data = DecPolyData.from_test(test)
            info = TestInfo.new_from_test(test, vectors.compliance, data)

            try:
                data.ret_pt = decrypt(test.key, test.ct, test.nonce, test.tag, test.aad)
            except NotImplementedError:
                logger.warning(
                    "ChaCha20-Poly1305 decrypt not implemented, test stopped"
                )
                return rd
            except ValueError as error:
                # All invalid tests should raise ValueError: InvalidNonceSize since the
                # nonce size is fixed, and ModifiedTag since the MAC verification should
                # fail.
                if test.type == TestType.INVALID:
                    info.ok()
                else:
                    info.fail(f"Caught ValueError: {str(error)}")
                res.add(info)
                continue
            except Exception as error:
                info.fail(f"Exception caught: {str(error)}")
                res.add(info)
                continue

            match (test.type, data.pt == data.ret_pt):
                case (TestType.VALID, True):
                    info.ok()
                case (TestType.VALID, False):
                    info.fail("Wrong ciphertext")
                case (TestType.INVALID, _):
                    # All invalid values should cause a ValueError and be caught when
                    # calling the function.
                    info.fail("Invalid test did not raise ValueError")
                case _:
                    raise ValueError(f"Invalid test type {test.type}")
            res.add(info)

    return rd


# -------------------------------------------------------------------------------------
# Output tests
# -------------------------------------------------------------------------------------


def test_output_encrypt(output: Path) -> ResultsDict:
    """Tests the output of ChaCha20 encryption.

    Reads operations from a plaintext file, uses the inputs with an internal
    implementation of ChaCha20 encryption, and compares the outputs to see if they
    match.

    Parsing errors are considered as test failures.

    Args:
        output:
            The plaintext file to read.

    Returns:
        A dictionary of results, containing one `Results`. If the file does not exist or
        reading from it failed, the dictionary will be empty.

    Note:
        The format is as follows:

        - One line per operation.
        - Lines are separated by newlines.
        - Lines that start with # are counted as comments and ignored.
        - Arguments are written in hexadecimal, except ``init_counter`` which is
          interpreted as an int.
        - Arguments are separated by slashes, no spaces.
        - Arguments in brackets are optional. If omitted, do not include the trailing
          slash.
        - The order of arguments is:

            key / plaintext / ciphertext / nonce [/init_counter]

        - The arguments are:
            - ``key`` is the symmetric key.
            - ``plaintext`` is the input plaintext.
            - ``ciphertext`` is the output ciphertext.
            - ``nonce`` is the nonce used.
            - ``init_counter`` is the optional initial position in the keystream to
              seek before encrypting. The value is in bytes.
    """
    rd = ResultsDict()

    try:
        with output.open("r") as file:
            lines = file.readlines()
    except IOError:
        logger.exception("Failed to read %s", str(output))
        return rd
    except FileNotFoundError:
        logger.error("Output file %s not found", str(output))
        return rd

    res = Results.new("Tests the output of ChaCha20 encryption", ["output_file"])
    rd.add(res)

    for tid, line in track(enumerate(lines, start=1), "Testing file"):
        if line.startswith("#"):
            continue
        info = TestInfo.new(
            tid, TestType.VALID, ["UserInput"], comment=f"Line number {tid}"
        )
        match line.rstrip().split("/"):
            case (k, p, c, n, i):
                key, pt, ct, nonce = map(lambda d: bytes.fromhex(d), (k, p, c, n))
                init_counter = int(i)
            case (k, p, c, n):
                key, pt, ct, nonce = map(lambda d: bytes.fromhex(d), (k, p, c, n))
                init_counter = 0
            case _ as args:
                info.fail(
                    f"Wrong number of arguments: got {len(args)}, expected 4 or 5"
                )
                res.add(info)
                continue

        try:
            ref_ct = _encrypt(key, pt, nonce, init_counter)
        except Exception as error:
            info.fail(f"Caught exception: {str(error)}")
            res.add(info)
            continue

        if ct == ref_ct:
            info.ok()
        else:
            info.fail("Wrong ciphertext")
        res.add(info)

    return rd


def test_output_decrypt(output: Path) -> ResultsDict:
    """Tests the output of ChaCha20 encryption.

    Reads operations from a plaintext file, uses the inputs with an internal
    implementation of ChaCha20 decryption, and compares the outputs to see if they
    match.

    Parsing errors are considered as test failures.

    Args:
        output:
            The plaintext file to read.

    Returns:
        A dictionary of results, containing one `Results`. If the file does not exist or
        reading from it failed, the dictionary will be empty.

    Note:
        The format is as follows:

        - One line per operation.
        - Lines are separated by newlines.
        - Lines that start with # are counted as comments and ignored.
        - Arguments are written in hexadecimal, except ``init_counter`` which is
          interpreted as an int.
        - Arguments are separated by slashes, no spaces.
        - Arguments in brackets are optional. If omitted, do not include the trailing
          slash.
        - The order of arguments is:

            key / ciphertext / plaintext / nonce [/init_counter]

        - The arguments are:
            - ``key`` is the symmetric key.
            - ``ciphertext`` is the input ciphertext.
            - ``plaintext`` is the output plaintext.
            - ``nonce`` is the nonce used.
            - ``init_counter`` is the optional initial position in the keystream to
              seek before encrypting. The value is in bytes.
    """
    rd = ResultsDict()

    try:
        with output.open("r") as file:
            lines = file.readlines()
    except IOError:
        logger.exception("Failed to read %s", str(output))
        return rd
    except FileNotFoundError:
        logger.error("Output file %s not found", str(output))
        return rd

    res = Results.new("Tests the output of ChaCha20 decryption", ["output_file"])
    rd.add(res)

    for tid, line in track(enumerate(lines, start=1), "Testing file"):
        if line.startswith("#"):
            continue
        info = TestInfo.new(
            tid, TestType.VALID, ["UserInput"], comment=f"Line number {tid}"
        )
        match line.rstrip().split("/"):
            case (k, c, p, n, i):
                key, ct, pt, nonce = map(lambda d: bytes.fromhex(d), (k, c, p, n))
                init_counter = int(i)
            case (k, c, p, n):
                key, ct, pt, nonce = map(lambda d: bytes.fromhex(d), (k, c, p, n))
                init_counter = 0
            case _ as args:
                info.fail(
                    f"Wrong number of arguments: got {len(args)}, expected 4 or 5"
                )
                res.add(info)
                continue

        try:
            ref_pt = _decrypt(key, ct, nonce, init_counter)
        except Exception as error:
            info.fail(f"Caught exception: {str(error)}")
            res.add(info)
            continue

        if pt == ref_pt:
            info.ok()
        else:
            info.fail("Wrong plaintext")
        res.add(info)

    return rd


def test_output_encrypt_poly(output: Path) -> ResultsDict:
    """Tests the output of ChaCha20-Poly1305 encryption.

    Reads operations from a plaintext file, uses the inputs with an internal
    implementation of ChaCha20-Poly1305 encryption, and compares the outputs to see if
    they match.

    Parsing errors are considered as test failures.

    Args:
        output:
            The plaintext file to read.

    Returns:
        A dictionary of results, containing one `Results`. If the file does not exist or
        reading from it failed, the dictionary will be empty.

    Note:
        The format is as follows:

        - One line per operation.
        - Lines are separated by newlines.
        - Lines that start with # are counted as comments and ignored.
        - Arguments are written in hexadecimal, except ``init_counter`` which is
          interpreted as an int.
        - Arguments are separated by slashes, no spaces.
        - Arguments in brackets are optional. If omitted, do not include the trailing
          slash.
        - The order of arguments is:

            key / plaintext / ciphertext / nonce / tag [/ aad]

        - The arguments are:
            - ``key`` is the symmetric key.
            - ``plaintext`` is the input plaintext.
            - ``ciphertext`` is the output ciphertext.
            - ``nonce`` is the nonce used.
            - ``tag`` is the MAC tag.
            - ``aad`` is the optional additional data.
    """
    rd = ResultsDict()

    try:
        with output.open("r") as file:
            lines = file.readlines()
    except IOError:
        logger.exception("Failed to read %s", str(output))
        return rd
    except FileNotFoundError:
        logger.error("Output file %s not found", str(output))
        return rd

    res = Results.new(
        "Tests the output of ChaCha20-Poly1305 encryption", ["output_file"]
    )
    rd.add(res)

    for tid, line in track(enumerate(lines, start=1), "Testing file"):
        if line.startswith("#"):
            continue
        info = TestInfo.new(
            tid, TestType.VALID, ["UserInput"], comment=f"Line number {tid}"
        )
        # Let mypy know that aad can be None.
        aad: bytes | None
        match line.rstrip().split("/"):
            case (k, p, c, n, t, a):
                key, pt, ct, nonce, tag, aad = map(
                    lambda x: bytes.fromhex(x), (k, p, c, n, t, a)
                )
            case (k, p, c, n, t):
                key, pt, ct, nonce, tag = map(
                    lambda x: bytes.fromhex(x), (k, p, c, n, t)
                )
                aad = None
            case _ as args:
                info.fail(
                    f"Wrong number of arguments: got {len(args)}, expected 5 or 6"
                )
                res.add(info)
                continue

        try:
            ref_ct, ref_tag = _encrypt_poly(key, pt, nonce, aad)
        except ValueError as error:
            info.fail(f"Caught ValueError: {str(error)}")
            res.add(info)
            continue

        match (ref_ct == ct, ref_tag == tag):
            case (True, True):
                info.ok()
            case (True, False):
                info.fail("Wrong tag")
            case (False, True):
                info.fail("Wrong ciphertext")
            case _:
                info.fail("Wrong ciphertext and tag")
        res.add(info)

    return rd


def test_output_decrypt_poly(output: Path) -> ResultsDict:
    """Tests the output of ChaCha20-Poly1305 decryption.

    Reads operations from a plaintext file, uses the inputs with an internal
    implementation of ChaCha20-Poly1305 decryption, and compares the outputs to see if
    they match.

    Parsing errors are considered as test failures.

    Args:
        output:
            The plaintext file to read.

    Returns:
        A dictionary of results, containing one `Results`. If the file does not exist or
        reading from it failed, the dictionary will be empty.

    Note:
        The format is as follows:

        - One line per operation.
        - Lines are separated by newlines.
        - Lines that start with # are counted as comments and ignored.
        - Arguments are written in hexadecimal, except ``init_counter`` which is
          interpreted as an int.
        - Arguments are separated by slashes, no spaces.
        - Arguments in brackets are optional. If omitted, do not include the trailing
          slash.
        - The order of arguments is:

            key / ciphertext / plaintext / nonce / tag [/ aad]

        - The arguments are:
            - ``key`` is the symmetric key.
            - ``ciphertext`` is the output ciphertext.
            - ``plaintext`` is the input plaintext.
            - ``nonce`` is the nonce used.
            - ``tag`` is the MAC tag.
            - ``aad`` is the optional additional data.
    """
    rd = ResultsDict()

    try:
        with output.open("r") as file:
            lines = file.readlines()
    except IOError:
        logger.exception("Failed to read %s", str(output))
        return rd
    except FileNotFoundError:
        logger.error("Output file %s not found", str(output))
        return rd

    res = Results.new(
        "Tests the output of ChaCha20-Poly1305 decryption", ["output_file"]
    )
    rd.add(res)

    for tid, line in track(enumerate(lines, start=1), "Testing file"):
        if line.startswith("#"):
            continue
        info = TestInfo.new(
            tid, TestType.VALID, ["UserInput"], comment=f"Line number {tid}"
        )
        # Let mypy know that aad can be None.
        aad: bytes | None
        match line.rstrip().split("/"):
            case (k, c, p, n, t, a):
                key, ct, pt, nonce, tag, aad = map(
                    lambda x: bytes.fromhex(x), (k, c, p, n, t, a)
                )
            case (k, c, p, n, t):
                key, ct, pt, nonce, tag = map(
                    lambda x: bytes.fromhex(x), (k, c, p, n, t)
                )
                aad = None
            case _ as args:
                info.fail(
                    f"Wrong number of arguments: got {len(args)}, expected 5 or 6"
                )
                res.add(info)
                continue

        try:
            ref_pt = _decrypt_poly(key, ct, nonce, tag, aad)
        except ValueError as error:
            info.fail(f"Caught ValueError: {error}")
            res.add(info)
            continue

        if ref_pt == pt:
            info.ok()
        else:
            info.fail("Wrong plaintext")
        res.add(info)

    return rd


# -------------------------------------------------------------------------------------
# Python harness
# -------------------------------------------------------------------------------------


def test_harness_python(
    harness: Path, compliance: bool, resilience: bool
) -> ResultsDict:
    """Tests a Python harness for ChaCha20.

    Args:
        harness:
            The harness to load and test.
        compliance:
            Whether to use compliance test vectors.
        resilience:
            Whether to use resilience test vectors.

    Returns:
        A dictionary of :class:`Results`, at least one per test.
    """
    rd = ResultsDict()
    logger.info("Testing Python harness: %s", str(harness.name))
    sys.path.insert(0, str(harness.parent.absolute()))
    already_imported = harness.stem in sys.modules.keys()
    try:
        module_harness = importlib.import_module(harness.stem)
    except ModuleNotFoundError:
        logger.exception("Cannot import wrapper %s", harness.stem)
        return rd
    if already_imported:
        logger.debug("Reloading Python harness: %s", harness.stem)
        module_harness = importlib.reload(module_harness)

    for name, func in inspect.getmembers(module_harness, inspect.isfunction):
        match name.split("_"):
            case ["CC", "ChaCha20", "encrypt"]:
                rd |= test_encrypt(func, compliance, resilience)
            case ["CC", "ChaCha20", "decrypt"]:
                rd |= test_decrypt(func, compliance, resilience)
            case ["CC", "ChaCha20", "encrypt", "poly"]:
                rd |= test_encrypt_poly(func, compliance, resilience)
            case ["CC", "ChaCha20", "decrypt", "poly"]:
                rd |= test_decrypt_poly(func, compliance, resilience)
            case ["CC", "ChaCha20", ("encrypt" | "decrypt"), *opt]:
                logger.error("Invalid harness options: %s", ", ".join(opt))
            case ["CC", "ChaCha20", op, *_]:
                logger.error("Invalid harness operation: %s", op)
            case _:
                # May include other functions, just ignore them.
                pass

    return rd


# -------------------------------------------------------------------------------------
# C harness
# -------------------------------------------------------------------------------------


def _test_harness_enc(ffi: cffi.FFI, lib, compliance: bool, resilience: bool):
    """Tests a harness for ChaCha20.encrypt."""
    logger.info("Testing harness function CC_ChaCha20_encrypt")

    ffi.cdef(
        """int CC_ChaCha20_encrypt(
                uint8_t *ciphertext, const uint8_t *plaintext,
                size_t text_size, const uint8_t key[32],
                const uint8_t *nonce, size_t nonce_size,
                uint64_t init_counter);
        """
    )
    lib_enc = lib.CC_ChaCha20_encrypt

    def enc(key: bytes, pt: bytes, nonce: bytes, init_counter: int = 0) -> bytes:
        c_key = ffi.new("uint8_t[]", key)
        c_pt = ffi.new("uint8_t[]", pt)
        c_ct = ffi.new(f"uint8_t[{len(pt)}]")
        c_nonce = ffi.new("uint8_t[]", nonce)

        rc = lib_enc(
            c_ct,
            c_pt,
            len(pt),
            c_key,
            c_nonce,
            len(nonce),
            ffi.cast("uint32_t", init_counter),
        )
        if rc == 1:
            return bytes(c_ct)
        else:
            raise ValueError(f"CC_ChaCha20_encrypt failed with status {rc}")

    return test_encrypt(enc, compliance, resilience)


def _test_harness_dec(ffi: cffi.FFI, lib, compliance: bool, resilience: bool):
    """Tests a harness for ChaCha20.decrypt."""
    logger.info("Testing harness function CC_ChaCha20_decrypt")

    ffi.cdef(
        """int CC_ChaCha20_decrypt(
                uint8_t *plaintext, const uint8_t *ciphertext,
                size_t text_size, const uint8_t key[32],
                const uint8_t *nonce, size_t nonce_size,
                uint32_t init_counter);
        """
    )
    lib_dec = lib.CC_ChaCha20_decrypt

    def dec(key: bytes, ct: bytes, nonce: bytes, init_counter: int = 0) -> bytes:
        c_key = ffi.new("uint8_t[]", key)
        c_ct = ffi.new("uint8_t[]", ct)
        c_pt = ffi.new(f"uint8_t[{len(ct)}]")
        c_nonce = ffi.new("uint8_t[]", nonce)

        rc = lib_dec(
            c_pt,
            c_ct,
            len(ct),
            c_key,
            c_nonce,
            len(nonce),
            ffi.cast("uint32_t", init_counter),
        )
        if rc == 1:
            return bytes(c_pt)
        else:
            raise ValueError(f"CC_ChaCha20_decrypt failed with status {rc}")

    return test_decrypt(dec, compliance, resilience)


def _test_harness_enc_poly(
    ffi: cffi.FFI, lib, compliance: bool, resilience: bool
) -> ResultsDict:
    """Tests a harness for ChaCha20-Poly1305 encryption."""
    fname = "CC_ChaCha20_encrypt_poly"
    logger.info("Testing harness function %s", fname)

    ffi.cdef(
        f"""int {fname}(
                uint8_t *ciphertext, uint8_t mac[16],
                const uint8_t *plaintext, size_t text_size,
                const uint8_t key[32], const uint8_t *nonce, size_t nonce_size,
                const uint8_t *aad, size_t aad_size);
        """
    )
    lib_enc = getattr(lib, fname)

    def enc(key: bytes, pt: bytes, nonce: bytes, aad: bytes) -> tuple[bytes, bytes]:
        c_key = ffi.new("uint8_t[]", key)
        c_pt = ffi.new("uint8_t[]", pt)
        c_ct = ffi.new(f"uint8_t[{len(pt)}]")
        c_nonce = ffi.new("uint8_t[]", nonce)
        c_tag = ffi.new("uint8_t[16]")
        if aad is not None:
            c_aad = ffi.new("uint8_t[]", aad)
            c_aad_size = len(aad)
        else:
            c_aad = ffi.NULL
            c_aad_size = 0

        rc = lib_enc(
            c_ct, c_tag, c_pt, len(pt), c_key, c_nonce, len(nonce), c_aad, c_aad_size
        )
        if rc == 1:
            return bytes(c_ct), bytes(c_tag)
        else:
            raise ValueError(f"{fname} failed with status {rc}")

    return test_encrypt_poly(enc, compliance, resilience)


def _test_harness_dec_poly(
    ffi: cffi.FFI, lib, compliance: bool, resilience: bool
) -> ResultsDict:
    """Tests a harness for ChaCha20-Poly1305 decryption."""
    fname = "CC_ChaCha20_decrypt_poly"
    logger.info("Testing harness function %s", fname)

    ffi.cdef(
        f"""int {fname}(
                uint8_t *plaintext, const uint8_t *ciphertext, size_t text_size,
                const uint8_t key[32], const uint8_t mac[16],
                const uint8_t *nonce, size_t nonce_size,
                const uint8_t *aad, size_t aad_size);
        """
    )
    lib_dec = getattr(lib, fname)

    def dec(
        key: bytes, ct: bytes, nonce: bytes, tag: bytes, aad: bytes
    ) -> bytes | None:
        c_key = ffi.new("uint8_t[]", key)
        c_ct = ffi.new("uint8_t[]", ct)
        c_pt = ffi.new(f"uint8_t[{len(ct)}]")
        c_nonce = ffi.new("uint8_t[]", nonce)
        c_tag = ffi.new("uint8_t[]", tag)
        if aad is not None:
            c_aad = ffi.new("uint8_t[]", aad)
            c_aad_size = len(aad)
        else:
            c_aad = ffi.NULL
            c_aad_size = 0

        rc = lib_dec(
            c_pt, c_ct, len(ct), c_key, c_tag, c_nonce, len(nonce), c_aad, c_aad_size
        )
        if rc == 1:
            return bytes(c_pt)
        else:
            raise ValueError(f"{fname} failed with status {rc}")

    return test_decrypt_poly(dec, compliance, resilience)


def test_lib(
    ffi: cffi.FFI, lib, functions: list[str], compliance: bool, resilience: bool
) -> ResultsDict:
    """Tests functions from a shared library.

    Args:
        ffi:
            The FFI instance.
        lib:
            The dlopen'd library.
        functions:
            A list of CC_ChaCha20 functions to test.
        compliance:
            Whether to use compliance test vectors.
        resilience:
            Whether to use resilience test vectors.
    """
    rd = ResultsDict()
    logger.info("Found harness functions %s", ", ".join(functions))

    for function in functions:
        match function.split("_"):
            case ["CC", "ChaCha20", "encrypt"]:
                rd |= _test_harness_enc(ffi, lib, compliance, resilience)
            case ["CC", "ChaCha20", "decrypt"]:
                rd |= _test_harness_dec(ffi, lib, compliance, resilience)
            case ["CC", "ChaCha20", "encrypt", "poly"]:
                rd |= _test_harness_enc_poly(ffi, lib, compliance, resilience)
            case ["CC", "ChaCha20", "decrypt", "poly"]:
                rd |= _test_harness_dec_poly(ffi, lib, compliance, resilience)
            case ["CC", "ChaCha20", ("encrypt" | "decrypt"), *opt]:
                logger.error("Invalid harness options: %s", ", ".join(opt))
            case ["CC", "ChaCha20", op, *_]:
                logger.error("Invalid harness operation: %s", op)
            case _:
                pass

    return rd
