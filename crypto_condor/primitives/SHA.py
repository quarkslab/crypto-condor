"""Module for the SHA-1, SHA-2, and SHA-3 primitives."""

import importlib
import logging
import subprocess
import sys
from pathlib import Path
from typing import Protocol

import attrs
import strenum
from Crypto.Hash import (
    SHA1,
    SHA3_224,
    SHA3_256,
    SHA3_384,
    SHA3_512,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
)
from rich.progress import track

from crypto_condor.primitives.common import DebugInfo, Results, ResultsDict, TestType
from crypto_condor.vectors.SHA import Algorithm, Orientation, ShaVectors

logger = logging.getLogger(__name__)


def __dir__():  # pragma: no cover
    return [
        # Enums
        Wrapper.__name__,
        # Protocols
        HashFunction.__name__,
        # Dataclasses
        ShaData.__name__,
        # Functions
        test.__name__,
        run_wrapper.__name__,
        verify_file.__name__,
        # Imported
        Algorithm.__name__,
        Orientation.__name__,
    ]


# --------------------------- Enums ---------------------------------------------------


class Wrapper(strenum.StrEnum):
    """Defines the available wrappers."""

    PYTHON = "Python"
    C = "C"


# --------------------------- Protocols -----------------------------------------------


class HashFunction(Protocol):
    """Represents a hash function.

    Hash functions must behave like :attr:`__call__` to be tested with this module.
    """

    def __call__(self, data: bytes) -> bytes:
        """Hashes the given data.

        Args:
            data: The input data.

        Returns:
            The resulting hash.
        """
        ...  # pragma: no cover (protocol)


# --------------------------- Dataclasses ---------------------------------------------


@attrs.define
class ShaData:
    """Debug data for SHA tests.

    Args:
        info: Common debug info, see :class:`crypto_condor.primitives.common.DebugInfo`.
        message: The message to hash.
        expected: The expected digest.
        digest: The resulting digest.
    """

    info: DebugInfo
    message: bytes
    expected: bytes
    digest: bytes | None | None

    def __str__(self) -> str:
        """Printable representation of the test."""
        s = str(self.info)
        s += f"message = {self.message.hex()}\n"
        s += f"expected = {self.expected.hex()}\n"
        s += f"digest = {self.digest.hex() if self.digest else '<none>'}\n"
        return s


@attrs.define
class ShaMcData:
    """Debug data for Monte-Carlo tests.

    Args:
        info: Common debug info, see :class:`crypto_condor.primitives.common.DebugInfo`.
        seed: The initial seed.
    """

    info: DebugInfo
    seed: bytes

    def __str__(self) -> str:
        """Returns a string representation."""
        s = str(self.info)
        s += f"seed = {self.seed.hex()}\n"
        return s


@attrs.define
class ShaVerifyData:
    """Debug data for :func:`verify_file`.

    The difference between this class and :class:`ShaData` is that the arguments of this
    class can all (except for info) can be None. This can happen when the line being
    verified could not be parsed, so not even the message can be recovered.

    Args:
        info: Common debug info, see :class:`crypto_condor.primitives.common.DebugInfo`.
        message: The message to hash.
        expected: The expected digest.
        digest: The resulting digest.
    """

    info: DebugInfo
    message: bytes | None = None
    expected: bytes | None = None
    digest: bytes | None = None

    def __str__(self) -> str:
        """Printable representation of the test."""
        s = str(self.info)
        if self.message is not None:
            s += f"message = {self.message.hex()}\n"
        if self.expected is not None:
            s += f"expected = {self.expected.hex()}\n"
        if self.digest is not None:
            s += f"digest = {self.digest.hex()}\n"
        return s


# --------------------------- Internal ------------------------------------------------


def _sha(algorithm: Algorithm, msg: bytes) -> bytes:
    """Hashes a message.

    Args:
        algorithm: The hash algorithm to use.
        msg: The message to hash.

    Returns:
        The digest.

    Notes:
        For internal use, uses :mod:`Crypto.Hash`.
    """
    match str(algorithm):
        case "SHA-1":
            return SHA1.new(msg).digest()
        case "SHA-224":
            return SHA224.new(msg).digest()
        case "SHA-256":
            return SHA256.new(msg).digest()
        case "SHA-384":
            return SHA384.new(msg).digest()
        case "SHA-512":
            return SHA512.new(msg).digest()
        case "SHA-512/224":
            return SHA512.new(msg, "224").digest()
        case "SHA-512/256":
            return SHA512.new(msg, "256").digest()
        case "SHA3-224":
            return SHA3_224.new(msg).digest()
        case "SHA3-256":
            return SHA3_256.new(msg).digest()
        case "SHA3-384":
            return SHA3_384.new(msg).digest()
        case "SHA3-512":
            return SHA3_512.new(msg).digest()
        case _:  # pragma: no cover (mypy)
            raise ValueError("Unknown hash algorithm %s" % str(algorithm))


# --------------------------- Test functions ------------------------------------------


def test(
    hash_function: HashFunction,
    hash_algorithm: Algorithm,
    orientation: Orientation = Orientation.BYTE,
) -> ResultsDict:
    """Tests a SHA implementation.

    Runs NIST test vectors on the given function. The function to test must conform to
    the :protocol:`HashFunction` protocol.

    Args:
        hash_function: The implementation to test.
        hash_algorithm: The hash algorithm implemented by :attr:`hash_function`.
        orientation: The orientation of the implementation, either bit- or
            byte-oriented.

    Returns:
        A :class:`ResultsDict` containing the results of short message (``short``), long
        message (``long``), and Monte-Carlo (``monte-carlo``) tests.

    Example:
        First import the SHA module.

        >>> from crypto_condor.primitives import SHA

        Let's test PyCryptodome's implementation of SHA-256. For this, we need to wrap
        the SHA256 class so it behaves like :protocol:`HashFunction`.

        >>> from Crypto.Hash import SHA256

        >>> def my_sha256(data: bytes) -> bytes:
        ...     return SHA256.new(data=data).digest()

        We define the parameters to test.

        >>> algorithm = SHA.Algorithm.SHA_256
        >>> orientation = SHA.Orientation.BYTE

        And call :func:`test` on our function and selected parameters.

        >>> results_dict = SHA.test(my_sha256, algorithm, orientation)
        [NIST] ...
        >>> assert results_dict.check()
    """
    vectors = ShaVectors.load(hash_algorithm, orientation)
    is_sha3 = str(hash_algorithm).startswith("SHA3-")

    short_results = Results(
        "SHA",
        f"test_sha ({'SHA-3' if is_sha3 else str(hash_algorithm)})",
        "NIST short message vectors",
        {"hash_algorithm": hash_algorithm, "orientation": orientation},
    )
    long_results = Results(
        "SHA",
        f"test_sha ({'SHA-3' if is_sha3 else str(hash_algorithm)})",
        "NIST long message vectors",
        {"hash_algorithm": hash_algorithm, "orientation": orientation},
    )
    mc_results = Results(
        "SHA",
        f"test_sha ({'SHA-3' if is_sha3 else str(hash_algorithm)})",
        "NIST Monte-Carlo vectors",
        {"hash_algorithm": hash_algorithm, "orientation": orientation},
    )

    for tid, test in track(
        enumerate(vectors.short_msg.tests, start=1), "[NIST] short message vectors"
    ):
        info = DebugInfo(tid, TestType.VALID, ["Compliance"])
        try:
            digest = hash_function(test.msg)
            if len(digest) * 8 != hash_algorithm.digest_size:
                raise ValueError(
                    "Wrong digest size, expected %d, got %d"
                    % (hash_algorithm.digest_size, len(digest) * 8)
                )
        except Exception as error:
            info.error_msg = f"Error running hash function: {str(error)}"
            logger.debug("Error running hash function", exc_info=True)
            data = ShaData(info, test.msg, test.md, None)
            short_results.add(data)
            continue

        if digest == test.md:
            info.result = True
        else:
            info.error_msg = "Wrong digest"
        data = ShaData(info, test.msg, test.md, digest)
        short_results.add(data)

    for tid, test in track(
        enumerate(vectors.long_msg.tests, start=1), "[NIST] long message vectors"
    ):
        info = DebugInfo(tid, TestType.VALID, ["Compliance"])
        try:
            digest = hash_function(test.msg)
            if len(digest) * 8 != hash_algorithm.digest_size:
                raise ValueError(
                    "Wrong digest size, expected %d, got %d"
                    % (hash_algorithm.digest_size, len(digest) * 8)
                )
        except Exception as error:
            info.error_msg = f"Error running hash function: {str(error)}"
            logger.debug("Error running hash function", exc_info=True)
            data = ShaData(info, test.msg, test.md, None)
            long_results.add(data)
            continue
        if digest == test.md:
            info.result = True
        else:
            info.error_msg = "Wrong digest"
        data = ShaData(info, test.msg, test.md, digest)
        long_results.add(data)

    # The Monte-Carlo tests are not built the same way for SHA-2 and SHA-3.
    if is_sha3:
        # The specification of the test is in section 6.2.3 of
        # https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha3vs.pdf
        info = DebugInfo(1, TestType.VALID, ["Compliance"])
        res = True
        mc_vectors = vectors.montecarlo
        md = mc_vectors.seed
        for j in track(range(0, 100), "[NIST] Monte-Carlo vectors"):
            for _ in range(1, 1001):
                msg = md
                md = hash_function(msg)
            if md != mc_vectors.checkpoints[j]:
                res = False
                break
        if res:
            info.result = True
        else:
            info.error_msg = f"Failed at checkpoint {j}"
        mc_data = ShaMcData(info, mc_vectors.seed)
        mc_results.add(mc_data)
    else:
        # The specification of this test is in section 6.4 of
        # https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/SHAVS.pdf
        info = DebugInfo(1, TestType.VALID, ["Compliance"])
        res = True
        mc_vectors = vectors.montecarlo
        seed = mc_vectors.seed
        for j in track(range(0, 100), "[NIST] Monte-Carlo vectors"):
            md0 = md1 = md2 = seed
            for _ in range(3, 1003):
                mi = md0 + md1 + md2
                try:
                    mdi = hash_function(mi)
                    if len(digest) * 8 != hash_algorithm.digest_size:
                        raise ValueError(
                            "Wrong digest size, expected %d, got %d"
                            % (hash_algorithm.digest_size, len(digest) * 8)
                        )
                except Exception as error:
                    info.error_msg = (
                        f"Error running hash function before checkpoint {j}:"
                        f" {str(error)}"
                    )
                    logger.debug("Error running hash function", exc_info=True)
                    res = False
                    break
                md0, md1, md2 = md1, md2, mdi
            if not res:
                break
            mdj = seed = mdi
            if mdj != mc_vectors.checkpoints[j]:
                res = False
                break
        if res:
            info.result = True
        elif not info.error_msg:
            info.error_msg = f"Failed at checkpoint {j}"
        mc_data = ShaMcData(info, seed)
        mc_results.add(mc_data)

    return ResultsDict(
        {"short": short_results, "long": long_results, "monte-carlo": mc_results}
    )


def _run_sha_python_wrapper(
    wrapper: Path, algorithm: Algorithm, orientation: Orientation
) -> ResultsDict:
    """Runs the Python SHA wrapper.

    Args:
        wrapper: The wrapper to test.
        algorithm: The SHA algorithm to test.
        orientation: The orientation of the implementation, either bit- or
            byte-oriented.
    """
    logger.info("Python SHA wrapper: %s", str(wrapper.name))
    sys.path.insert(0, str(wrapper.parent.absolute()))
    already_imported = wrapper.stem in sys.modules.keys()
    try:
        sha_wrapper = importlib.import_module(wrapper.stem)
    except ModuleNotFoundError as error:
        logger.error("Can't import wrapper: %s", str(error))
        raise
    if already_imported:
        logger.debug("Reloading SHA wrapper module %s", wrapper.stem)
        sha_wrapper = importlib.reload(sha_wrapper)
    results_dict = test(sha_wrapper.sha, algorithm, orientation)
    return results_dict


def _run_sha_c_wrapper(
    wrapper: Path, algorithm: Algorithm, orientation: Orientation
) -> ResultsDict:
    """Runs the C SHA wrapper.

    Args:
        wrapper: The executable wrapper to test.
        algorithm: The SHA algorithm to test.
        orientation: The orientation of the implementation, either bit- or
            byte-oriented.
    """

    def sha(data: bytes) -> bytes:
        args = [str(wrapper.absolute()), "--input", data.hex()]
        match algorithm:
            case "SHA-1":
                args += ["--digest-length", "20"]
            case "SHA-224" | "SHA-512/224" | "SHA3-224":
                args += ["--digest-length", "28"]
            case "SHA-256" | "SHA-512/256" | "SHA3-256":
                args += ["--digest-length", "32"]
            case "SHA-384" | "SHA3-384":
                args += ["--digest-length", "48"]
            case "SHA-512" | "SHA3-512":
                args += ["--digest-length", "64"]
            case _:
                raise ValueError("Unsupported algorithm %s" % algorithm)
        r = subprocess.run(args, capture_output=True, text=True)
        if r.returncode != 0:
            raise ValueError(
                "Subprocess failed running SHA wrapper (err: %s)" % r.returncode
            )
        digest = bytes.fromhex(r.stdout.rstrip())
        return digest

    return test(sha, algorithm, orientation)


def run_wrapper(
    wrapper: Path,
    # language: Wrapper,
    hash_algorithm: Algorithm,
    orientation: Orientation,
) -> ResultsDict:
    """Runs the corresponding wrapper.

    Args:
        wrapper: The wrapper to test.
        language: The language of the wrapper to run.
        hash_algorithm: The hash algorithm to test.
        orientation: The orientation of the implementation, either bit- or
            byte-oriented.

    Returns:
        A :class:`ResultsDict` containing the results of short message (``short``), long
        message (``long``), and Monte-Carlo (``monte-carlo``) tests.
    """
    if not wrapper.is_file():
        raise FileNotFoundError(f"SHA wrapper not found: {str(wrapper)}")

    if wrapper.suffix == ".py":
        return _run_sha_python_wrapper(wrapper, hash_algorithm, orientation)
    else:
        return _run_sha_c_wrapper(wrapper, hash_algorithm, orientation)


def verify_file(filename: str, hash_algorithm: Algorithm) -> Results:
    r"""Verifies SHA hashes.

    Tests hashes from a file. The file must follow the format described below.

    Format:
        - One set of arguments per line.
        - Lines are separated by newlines (``\n``).
        - Lines that start with '#' are counted as comments and ignored.
        - Arguments are written in hexadecimal and separated by slashes.
        - The order of arguments is:

        .. code::

            message/hash

    Args:
        filename: Name of the file to test.
        hash_algorithm: Hash algorithm used to generate the hashes.

    Returns:
        The results of hashing the message with the internal implementation and
        comparing with the expected output.

    Example:
        First import the SHA module.

        >>> from crypto_condor.primitives import SHA

        Let's generate a file of random messages and their hash.

        >>> import random
        >>> filename = "/tmp/crypto-condor-test/SHA-256-verify.txt"
        >>> algorithm = SHA.Algorithm.SHA_256
        >>> with open(filename, "w") as file:
        ...     for i in range(20):
        ...         message = random.randbytes(64)
        ...         digest = SHA._sha(algorithm, message)
        ...         line = f"{message.hex()}/{digest.hex()}\n"
        ...         _ = file.write(line)

        We call :func:`verify_file` on our test file.

        >>> results = SHA.verify_file(filename, algorithm)
        Testing ...
        >>> assert results.check()
    """
    try:
        with Path(filename).open("r") as file:
            lines = file.readlines()
    except OSError:
        logger.exception("Could not open %s", filename)
        raise

    results = Results(
        "SHA",
        "verify_file_sha",
        "Verifies the output of an implementation",
        {"filename": filename, "hash_algorithm": hash_algorithm},
    )

    for tid, line in track(enumerate(lines, start=1), "Testing hashes"):
        if line.startswith("#"):
            continue
        info = DebugInfo(
            tid, TestType.VALID, ["UserInput"], comment=f"Line number {tid}"
        )
        match line.rstrip().split("/"):
            case (msg, md):
                message, digest = map(bytes.fromhex, (msg, md))
            case _ as args:
                info.error_msg = f"Parsing error, expected 2 arguments got {len(args)}"
                data = ShaVerifyData(info)
                continue
        expected = _sha(hash_algorithm, message)
        if digest == expected:
            info.result = True
        else:
            info.error_msg = "Wrong digest"
        data = ShaVerifyData(info, message, expected, digest)
        results.add(data)

    return results
