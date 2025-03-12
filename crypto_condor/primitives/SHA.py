"""Module for the SHA-1, SHA-2, and SHA-3 primitives."""

import importlib
import inspect
import json
import logging
import subprocess
import sys
import warnings
from pathlib import Path
from typing import Protocol

import attrs
import cffi
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

from crypto_condor.primitives.common import (
    Results,
    ResultsDict,
    TestInfo,
    TestType,
)
from crypto_condor.vectors._sha.sha_pb2 import ShaTest, ShaVectors
from crypto_condor.vectors.SHA import Algorithm

logger = logging.getLogger(__name__)


def __dir__():  # pragma: no cover
    return [
        # Enums
        Wrapper.__name__,
        # Protocols
        HashFunction.__name__,
        # Functions
        test_digest.__name__,
        test_output_digest.__name__,
        # Wrapper
        test_wrapper.__name__,
        test_wrapper_python.__name__,
        # Harness
        test_lib.__name__,
        # Imported
        Algorithm.__name__,
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
class DigestData:
    """Debug data for :func:`test`.

    Args:
        msg:
            The input message.
        md:
            The expected digest.

    Keyword Args:
        ret_md:
            The digest returned by the implementation.
    """

    msg: bytes
    md: bytes
    ret_md: bytes | None = None

    def __str__(self) -> str:
        """Returns a string representation."""
        return f"""msg = {self.msg.hex()}
md = {self.md.hex()}
returned md = {self.ret_md.hex() if self.ret_md is not None else "<none>"}
"""


@attrs.define
class MonteCarloData:
    """Debug data for Monte Carlo tests.

    Args:
        seed:
            The initial seed.
    """

    seed: bytes

    def __str__(self) -> str:
        """Returns a string representation."""
        return f"""seed = {self.seed.hex()}\n"""


@attrs.define
class VerifyData:
    """Debug data for :func:`test_output_digest`.

    Args:
        msg:
            The input message.
        md:
            The digest returned by the implementation.
        ref_md:
            The digest returned by the reference implementation.
    """

    msg: bytes
    md: bytes
    ref_md: bytes

    def __str__(self) -> str:
        """Returns a string representation."""
        return f"""msg = {self.msg.hex()}
md = {self.md.hex()}
reference md = {self.ref_md.hex()}
"""


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


def _load_vectors(algo: Algorithm) -> list[ShaVectors]:
    """Loads SHA vectors.

    Args:
        algo:
            The algorithm to load vectors of.

    Returns:
        A list of :class:`ShaVectors`.
    """
    vectors_dir = importlib.resources.files("crypto_condor") / "vectors/_sha"
    vectors = list()

    sources_file = vectors_dir / "sha.json"
    with sources_file.open("r") as file:
        sources = json.load(file)

    for filename in sources[algo]:
        vectors_file = vectors_dir / "pb2" / filename
        _vec = ShaVectors()
        logger.debug("Loading SHA vectors from %s", filename)
        try:
            _vec.ParseFromString(vectors_file.read_bytes())
        except Exception:
            logger.exception("Failed to load SHA vectors from %s", filename)
            continue
        vectors.append(_vec)

    return vectors


# --------------------------- Test functions ------------------------------------------


def test(
    hash_function: HashFunction,
    hash_algorithm: Algorithm,
    *,
    compliance: bool = True,
    resilience: bool = False,
) -> ResultsDict:
    """Tests a SHA implementation.

    Runs NIST test vectors on the given function. The function to test must conform to
    the :protocol:`HashFunction` protocol.

    Args:
        hash_function:
            The implementation to test.
        hash_algorithm:
            The hash algorithm implemented by :attr:`hash_function`.

    Keyword Args:
        compliance:
            Whether to use compliance test vectors.
        resilience:
            Whether to use resilience test vectors.

    Returns:
        A dictionary of results.

    .. versionchanged:: TODO(version)
        Removed the ``Orientation`` argument, added the ``compliance`` and
        ``resilience`` keywork arguments.

    .. deprecated:: TODO(version)
        Will be removed in a future version, use :func:`test_digest` instead.
    """
    warnings.warn("Use test_digest instead", DeprecationWarning, stacklevel=1)
    return test_digest(
        hash_function, hash_algorithm, compliance=compliance, resilience=resilience
    )


def test_digest(
    digest: HashFunction,
    algorithm: Algorithm,
    *,
    compliance: bool = True,
    resilience: bool = False,
) -> ResultsDict:
    """Tests a SHA implementation.

    Runs NIST test vectors on the given function. The function to test must conform to
    the :protocol:`HashFunction` protocol.

    Args:
        digest:
            The implementation to test.
        algorithm:
            The hash algorithm implemented by :attr:`digest`.

    Keyword Args:
        compliance:
            Whether to use compliance test vectors.
        resilience:
            Whether to use resilience test vectors.

    Returns:
        A dictionary of results.

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

        And call :func:`test` on our function and selected parameters.

        >>> results_dict = SHA.test_digest(my_sha256, algorithm)
        [SHA-256] Test digest ...
        >>> assert results_dict.check()

    .. versionadded:: TODO(version)
        Replaces the ``test`` function.
    """
    all_vectors = _load_vectors(algorithm)
    rd = ResultsDict()

    test: ShaTest
    for vectors in all_vectors:
        if not compliance and vectors.compliance:
            continue
        if not resilience and not vectors.compliance:
            continue

        res = Results.new(f"Test {str(algorithm)} digest", ["algorithm"])
        rd.add(res)

        for test in track(vectors.tests, rf"\[{algorithm}] Test digest"):
            info = TestInfo.new_from_test(test, vectors.compliance)
            data = DigestData(test.msg, test.md)
            try:
                md = digest(test.msg)
            except NotImplementedError:
                logger.warning("%s digest not implemented, skipped", algorithm)
                return rd
            except Exception as error:
                info.fail(f"Exception caught: {str(error)}", data)
                res.add(info)
                continue

            data.ret_md = md
            if len(md) * 8 != algorithm.digest_size:
                info.fail(f"Wrong digest size ({len(md) * 8})", data)
            elif md != test.md:
                info.fail("Wrong digest", data)
            else:
                info.ok(data)
            res.add(info)

        # Check if vectors contain a Monte Carlo test, skip otherwise.
        if not vectors.HasField("mc_test"):
            continue

        # The Monte-Carlo tests are not built the same way for SHA-2 and SHA-3.
        if algorithm.sha3:
            # The specification of the test is in section 6.2.3 of
            # https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha3vs.pdf
            info = TestInfo.new_from_test(vectors.mc_test, vectors.compliance)
            is_test_ok = True
            md = vectors.mc_test.seed
            for j in track(range(0, 100), rf"\[{str(algorithm)}] Monte-Carlo test"):
                if not res:
                    break
                for _ in range(1, 1001):
                    msg = md
                    try:
                        md = digest(msg)
                    except Exception as error:
                        logger.debug(
                            "Error running user-defined function: %s", str(error)
                        )
                        is_test_ok = False
                        break
                if md != vectors.mc_test.checkpoints[j]:
                    is_test_ok = False
            mc_data = MonteCarloData(vectors.mc_test.seed)
            if is_test_ok:
                info.ok(mc_data)
            else:
                info.fail(f"Failed at checkpoint {j}", mc_data)
            res.add(info)
        else:
            # The specification of this test is in section 6.4 of
            # https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/SHAVS.pdf
            info = TestInfo.new_from_test(vectors.mc_test, vectors.compliance)
            is_test_ok = True
            seed = vectors.mc_test.seed
            for j in track(range(0, 100), rf"\[{str(algorithm)}] Monte-Carlo test"):
                if not is_test_ok:
                    break
                md0 = md1 = md2 = seed
                for _ in range(3, 1003):
                    mi = md0 + md1 + md2
                    try:
                        mdi = digest(mi)
                        if len(mdi) * 8 != algorithm.digest_size:
                            raise ValueError(
                                "Wrong digest size, expected %d, got %d"
                                % (algorithm.digest_size, len(mdi) * 8)
                            )
                    except Exception as error:
                        info.fail(
                            f"Exception caught before checkpoint {j}: {str(error)}",
                            data,
                        )
                        logger.debug("Error running hash function", exc_info=True)
                        is_test_ok = False
                        break
                    md0, md1, md2 = md1, md2, mdi
                if not is_test_ok:
                    break
                mdj = seed = mdi
                if mdj != vectors.mc_test.checkpoints[j]:
                    is_test_ok = False

            mc_data = MonteCarloData(seed)
            if is_test_ok:
                info.ok(mc_data)
            elif info.err_msg is not None:
                # We already marked the test as failed because of an exception.
                pass
            else:
                info.fail(f"Failed at checkpoint {j}", mc_data)
            res.add(info)

    return rd


# --------------------------- Wrappers ------------------------------------------------


def test_wrapper_python(
    wrapper: Path, compliance: bool, resilience: bool
) -> ResultsDict:
    """Tests a Python SHA wrapper.

    Args:
        wrapper:
            A path to the wrapper to test.
        compliance:
            Whether to use compliance test vectors.
        resilience:
            Whether to use resilience test vectors.

    .. versionadded:: TODO(version)
    """
    logger.info("Running Python SHA wrapper: '%s'", str(wrapper.name))
    sys.path.insert(0, str(wrapper.parent.absolute()))
    already_imported = wrapper.stem in sys.modules.keys()
    try:
        sha_wrapper = importlib.import_module(wrapper.stem)
    except ModuleNotFoundError as error:
        logger.error("Can't import wrapper: '%s'", str(error))
        raise
    if already_imported:
        logger.debug("Reloading SHA wrapper: '%s'", wrapper.stem)
        sha_wrapper = importlib.reload(sha_wrapper)

    rd = ResultsDict()

    for func, _ in inspect.getmembers(sha_wrapper, inspect.isfunction):
        match func.split("_"):
            case ["CC", "SHA", *_algo, "digest"]:
                logger.info("Found CC_SHA function %s", func)
                try:
                    algo = Algorithm.from_wrapper(_algo)
                except ValueError:
                    logger.error("Invalid algorithm %s for SHA, skipped", _algo)
                    continue
                rd |= test_digest(
                    getattr(sha_wrapper, func),
                    algo,
                    compliance=compliance,
                    resilience=resilience,
                )
            case ["CC", "SHA", *_]:
                logger.warning("Ignored unknown CC_SHA function %s", func)
                continue
            case _:
                pass

    return rd


def test_wrapper(wrapper: Path, compliance: bool, resilience: bool) -> ResultsDict:
    """Tests a SHA wrapper.

    Calls the corresponding ``test_wrapper`` function based on the wrapper's extension.

    Args:
        wrapper:
            A path to the wrapper to test.
        compliance:
            Whether to use compliance test vectors.
        resilience:
            Whether to use resilience test vectors.

    Raises:
        FileNotFoundError:
            If the wrapper is not found.

    .. versionadded:: TODO(version)
        Replaces ``run_wrapper``.
    """
    if not wrapper.is_file():
        raise FileNotFoundError(f"Wrapper {str(wrapper)} not found")

    match wrapper.suffix:
        case ".py":
            return test_wrapper_python(wrapper, compliance, resilience)
        case _:
            raise ValueError(f"No runner for '{wrapper.suffix}' wrappers")


def _run_sha_c_wrapper(wrapper: Path, algorithm: Algorithm) -> ResultsDict:
    """Runs the C SHA wrapper.

    Args:
        wrapper:
            The executable wrapper to test.
        algorithm:
            The SHA algorithm to test.
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

    return test(sha, algorithm)


def verify_file(filename: str, hash_algorithm: Algorithm) -> ResultsDict:
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
        A dictionary of results.

    .. versionchanged:: TODO(version)
        Returns a :class:`ResultsDict` instead of :class:`Results`.

    .. deprecated:: TODO(version)
        Will be removed in a future version, use :func:`test_output_digest` instead.
    """
    warnings.warn("Use test_output_digest instead", DeprecationWarning, stacklevel=1)
    return test_output_digest(filename, hash_algorithm)


def test_output_digest(filename: str, algorithm: Algorithm) -> ResultsDict:
    r"""Tests a file of SHA hashes.

    The messages and the corresponding hashes are read from the file. The messages are
    hashed with a reference implementation and compared to those in the file. The test
    passes if the hashes match. Parsing errors count as failures.

    The file must follow the format described below.

    Format:
        - One set of arguments per line.
        - Lines are separated by newlines (``\n``).
        - Lines that start with '#' are counted as comments and ignored.
        - Arguments are written in hexadecimal and separated by slashes.
        - The order of arguments is:

        .. code::

            message/hash

    Args:
        filename:
            Name of the file to test.
        algorithm:
            Hash algorithm used to generate the hashes.

    Returns:
        A dictionary of results.

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

        >>> results = SHA.test_output_digest(filename, algorithm)
        Testing ...
        >>> assert results.check()
    """
    try:
        with Path(filename).open("r") as file:
            lines = file.readlines()
    except OSError:
        logger.exception("Could not open %s", filename)
        raise

    res = Results.new(f"Tests a file of {algorithm} hashes", ["filename", "algorithm"])

    for tid, line in track(enumerate(lines, start=1), "Testing hashes"):
        if line.startswith("#"):
            continue
        info = TestInfo.new(tid, TestType.VALID, ["UserInput"], f"Line number {tid}")
        match line.rstrip().split("/"):
            case (_msg, _md):
                msg, md = map(bytes.fromhex, (_msg, _md))
            case _ as args:
                info.fail(f"Failed to parse line {tid}, got {len(args)} arguments")
                continue
        ref_md = _sha(algorithm, msg)
        data = VerifyData(msg, md, ref_md)
        if md == ref_md:
            info.ok(data)
        else:
            info.fail("Wrong digest", data)
        res.add(info)

    return res


# --------------------------- Lib hook functions --------------------------------------


def _test_lib_digest(
    ffi: cffi.FFI,
    lib,
    function: str,
    algorithm: Algorithm,
    compliance: bool,
    resilience: bool,
) -> ResultsDict:
    logger.info("Testing harness function %s", function)

    ffi.cdef(
        f"""int {function}(uint8_t *digest, const size_t digest_size,
                            const uint8_t *input, size_t input_size);
        """
    )
    sha = getattr(lib, function)

    # The output size is fixed for a given algorithm so create the buffer in advance.
    c_md_len = algorithm.digest_size // 8
    c_buffer = ffi.new(f"uint8_t[{c_md_len}]")

    def _sha(data: bytes) -> bytes:
        c_data = ffi.new(f"uint8_t[{len(data)}]", data)
        ret_val = sha(c_buffer, c_md_len, c_data, len(data))
        if ret_val != 1:
            raise ValueError(f"{function} failed with code {ret_val}")
        return bytes(c_buffer)

    return test_digest(_sha, algorithm, compliance=compliance, resilience=resilience)


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
            A list of CC_SHA functions to test.
        compliance:
            Whether to use compliance test vectors.
        resilience:
            Whether to use resilience test vectors.
    """
    logger.info("Found harness functions %s", ", ".join(functions))

    results = ResultsDict()

    for function in functions:
        match function.split("_"):
            case ["CC", "SHA", *parts, "digest"]:
                try:
                    algo = Algorithm.from_wrapper(parts)
                except ValueError:
                    logger.error("Invalid algorithm SHA_%s", "_".join(parts))
                    continue
                results |= _test_lib_digest(
                    ffi, lib, function, algo, compliance, resilience
                )
            case _:
                logger.debug("Ignoring unknown CC_SHA function %s", function)

    return results
