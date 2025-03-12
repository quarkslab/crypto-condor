"""Module to test SHAKE implementations."""

import importlib
import inspect
import json
import logging
import sys
import warnings
from pathlib import Path
from typing import Protocol

import attrs
import cffi
import strenum
from cryptography.hazmat.primitives import hashes
from rich.progress import track

from crypto_condor.primitives.common import Results, ResultsDict, TestInfo, TestType
from crypto_condor.vectors._shake.shake_pb2 import ShakeTest, ShakeVectors

logger = logging.getLogger(__name__)


def __dir__():  # pragma: no cover
    return [
        # Enums
        Orientation.__name__,
        Algorithm.__name__,
        Wrapper.__name__,
        # Protocols
        Xof.__name__,
        # Functions
        test.__name__,
        run_python_wrapper.__name__,
    ]


# --------------------------- Enums ---------------------------------------------------


class Algorithm(strenum.StrEnum):
    """Supported extensible output functions."""

    SHAKE128 = "SHAKE128"
    SHAKE256 = "SHAKE256"


class Orientation(strenum.StrEnum):
    """Orientation of the implementation."""

    BIT = "bit"
    BYTE = "byte"


class Wrapper(strenum.StrEnum):
    """Defines the available wrappers."""

    PYTHON = "Python"


# --------------------------- Protocols -----------------------------------------------


class Xof(Protocol):
    """Represents a XOF.

    XOFs must behave like :attr:`__call__` to be tested with this module.
    """

    def __call__(self, data: bytes, output_length: int) -> bytes:
        """Produces digests of any desired length.

        Args:
            data: The input data.
            output_length: The desired length of the digest in bytes.

        Returns:
            The digest of the desired length.
        """
        ...  # pragma: no cover (protocol)


# --------------------------- Dataclasses ---------------------------------------------


@attrs.define
class ShakeData:
    """Debug data for SHAKE tests.

    Args:
        message: The message to hash.
        expected: The expected digest.
        result: The resulting digest.

    Notes:
        id starts at 1.
    """

    message: bytes
    expected: bytes
    result: bytes | None = None

    def __str__(self) -> str:
        """Printable representation of the test."""
        s = f"message = {self.message.hex()}\n"
        s += f"expected = {self.expected.hex()}\n"
        s += f"result = {self.result.hex() if self.result else '<none>'}\n"
        return s


@attrs.define
class ShakeMcData:
    """Debug data for Monte-Carlo tests.

    Args:
        seed: The initial seed.
    """

    seed: bytes

    def __str__(self) -> str:
        """Returns a string representation."""
        s = f"seed = {self.seed.hex()}\n"
        return s


# --------------------------- Test functions ------------------------------------------


def _load_vectors(algo: Algorithm, orient: Orientation) -> list[ShakeVectors]:
    """Loads vectors for a given algorithm and orientation.

    Returns:
        A list of vectors.
    """
    vectors_dir = importlib.resources.files("crypto_condor") / "vectors/_shake"
    vectors = list()

    sources_file = vectors_dir / "shake.json"
    with sources_file.open("r") as file:
        sources = json.load(file)

    for filename in sources[algo][orient]:
        vectors_file = vectors_dir / "pb2" / filename
        _vec = ShakeVectors()
        logger.debug("Loading SHAKE vectors from %s", str(filename))
        try:
            _vec.ParseFromString(vectors_file.read_bytes())
        except Exception:
            logger.exception("Failed to load SHAKE vectors from %s", str(filename))
            continue
        vectors.append(_vec)

    return vectors


def _left_most_bits(output: bytes, n: int) -> bytes:
    """Returns the n left-most bits of output.

    If the output is shorter than n, pad with zeroes to the right.
    """
    output_len = len(output) * 8
    if output_len > n:
        return output[: n // 8]
    elif output_len == n:
        return output
    else:
        return output + b"\0" * ((n - output_len) // 8)


def test(
    xof: Xof,
    algorithm: Algorithm,
    orientation: Orientation = Orientation.BYTE,
    *,
    compliance: bool = True,
    resilience: bool = False,
) -> ResultsDict:
    """Tests a SHAKE implementation.

    Args:
        xof: The function to test.
        algorithm: The algorithm of the XOF to test.
        orientation: The orientation of the implementation, either bit- or
            byte-oriented. Byte-oriented by default.

    Keyword Args:
        compliance: Whether to use compliance test vectors.
        resilience: Whether to use resilience test vectors.

    Returns:
        A dictionary of results.

    .. deprecated:: TODO(version)
        Will be removed in a future version, use :func:`test_digest` instead.
    """
    warnings.warn("Use test_digest instead", DeprecationWarning, stacklevel=1)
    return test_digest(
        xof, algorithm, orientation, compliance=compliance, resilience=resilience
    )


def test_digest(
    xof: Xof,
    algorithm: Algorithm,
    orientation: Orientation = Orientation.BYTE,
    *,
    compliance: bool = True,
    resilience: bool = False,
) -> ResultsDict:
    """Tests a SHAKE implementation.

    Args:
        xof: The function to test.
        algorithm: The algorithm of the XOF to test.
        orientation: The orientation of the implementation, either bit- or
            byte-oriented. Byte-oriented by default.

    Keyword Args:
        compliance: Whether to use compliance test vectors.
        resilience: Whether to use resilience test vectors.

    Returns:
        A dictionary of results.

    Example:
        Let's test hashlib.shake_128:

        >>> from crypto_condor.primitives import SHAKE
        >>> from hashlib import shake_128

        To return the digest, ``shake_128`` requires a call to its ``digest`` method so
        we wrap it in our own function to implement the :protocol:`Xof` protocol.

        >>> def my_shake128(data: bytes, output_length: int) -> bytes:
        ...     h = shake_128(data)
        ...     return h.digest(output_length)

        Now we test this implementation.

        >>> res = SHAKE.test_digest(my_shake128, SHAKE.Algorithm.SHAKE128)
        [SHAKE128][NIST CAVP] ...
        >>> assert res.check()

    .. versionadded:: TODO(version)
    """
    all_vectors = _load_vectors(algorithm, orientation)
    rd = ResultsDict()

    test: ShakeTest
    for vectors in all_vectors:
        if not compliance and vectors.compliance:
            continue
        if not resilience and not vectors.compliance:
            continue

        res = Results.new("Tests a SHAKE implementation", ["algorithm", "orientation"])
        rd.add(res)

        for test in track(
            vectors.tests, rf"\[{algorithm}]\[{vectors.source}] Testing XOF"
        ):
            info = TestInfo.new_from_test(test, vectors.compliance)
            data = ShakeData(test.msg, test.out)
            try:
                output = xof(test.msg, len(test.out))
            except NotImplementedError:
                logger.warning(f"{algorithm} not implemented, skipped")
                return rd
            except Exception as error:
                info.fail(f"Digest failed with exception: {str(error)}", data)
                res.add(info)
                logger.debug("Exception caught", exc_info=True)
                continue
            data.result = output
            if output == test.out:
                info.ok(data)
            else:
                info.fail("Wrong digest", data)
            res.add(info)

        # Continue to the next vectors if current has no Monte-Carlo test.
        if not vectors.HasField("mc_test"):
            continue

        # Monte-Carlo vectors.
        mv = vectors.mc_test
        # Start with the 'seed' message.
        output = mv.seed
        # max_len and min_len are lengths in bytes.
        max_len = (mv.max_len + 7) // 8
        min_len = (mv.min_len + 7) // 8
        # Start with max_len.
        output_len = max_len
        res = True
        for j in track(
            range(100),
            rf"\[{algorithm}]\[{vectors.source}] Testing Monte-Carlo vectors",
        ):
            for _ in range(1, 1001):
                msg = _left_most_bits(output, 128)
                output = xof(msg, output_len)
                # Get the 16 rightmost bits as int.
                rb = int.from_bytes(output[-2:], "big")
                rg = max_len - min_len + 1
                output_len = min_len + (rb % rg)
            if output != mv.checkpoints[j]:
                res = False
                break
        info = TestInfo.new_from_test(mv, vectors.compliance)
        mc_data = ShakeMcData(mv.seed)
        if res:
            info.ok(mc_data)
        else:
            info.fail(f"Failed at checkpoint {j}", mc_data)

    return rd


def test_output_digest(output: Path, algorithm: Algorithm) -> ResultsDict:
    r"""Tests the output of a SHAKE implementation.

    Args:
        output: A path to the output file.
        algorithm: The algorithm to test.

    Returns:
        A dictionary of results.

    Format:
        - One line per operation, separated by newlines ``\n``.
        - Lines starting with ``#`` are considered comments and ignored.
        - Values are written in hexadecimal.
        - Values are separated by forward slashes ``/``.
        - The order of the values is:

        .. code::

            msg/out

        Where:
            - ``msg`` is the input message to hash.
            - ``out`` is the result.

    .. versionadded:: TODO(version)
    """
    if not output.is_file():
        raise FileNotFoundError(f"No output file {(str(output))} found")
    with output.open("r") as file:
        lines = file.readlines()

    results = Results.new("Tests the output of SHAKE", ["output", "algorithm"])
    index: int
    line: str
    for index, line in track(
        enumerate(lines, 1), rf"\[{str(algorithm)}] Testing output"
    ):
        if line.startswith("#"):
            continue
        line = line.strip()
        match line.split("/"):
            case [_msg, _out]:
                msg, out = map(bytes.fromhex, (_msg, _out))
            case _:
                logger.error(f"Failed to parse line {index} (expected 2 values)")
                continue
        info = TestInfo.new(index, TestType.VALID, ["UserInput"])
        data = ShakeData(msg, out)
        if algorithm == Algorithm.SHAKE128:
            _hash = hashes.Hash(hashes.SHAKE128(len(out)))
        else:
            _hash = hashes.Hash(hashes.SHAKE256(len(out)))
        _hash.update(msg)
        ret_out = _hash.finalize()

        data.result = ret_out

        if ret_out == out:
            info.ok(data)
        else:
            info.fail("Outputs do not match", data)
        results.add(info)

    rd = ResultsDict()
    rd.add(results)
    return rd


# --------------------------- Runners -------------------------------------------------


def run_python_wrapper(wrapper: Path, compliance: bool, resilience: bool):
    """Runs the Python SHAKE wrapper.

    Args:
        wrapper: A path to wrapper to run.
        compliance: Whether to use compliance test vectors.
        resilience: Whether to use resilience test vectors.
    """
    logger.info("Running Python SHAKE wrapper: '%s'", str(wrapper.name))
    sys.path.insert(0, str(wrapper.parent.absolute()))
    already_imported = wrapper.stem in sys.modules.keys()
    try:
        shake_wrapper = importlib.import_module(wrapper.stem)
    except ModuleNotFoundError as error:
        logger.error("Can't import wrapper: '%s'", str(error))
        raise
    if already_imported:
        logger.debug("Reloading SHAKE wrapper: '%s'", wrapper.stem)
        shake_wrapper = importlib.reload(shake_wrapper)

    rd = ResultsDict()

    for function, _ in inspect.getmembers(shake_wrapper, inspect.isfunction):
        match function.split("_"):
            case ["CC", "SHAKE", _algo, "digest"]:
                logger.info("Found CC_SHAKE function %s", function)
                try:
                    algo = Algorithm(f"SHAKE{_algo}")
                except ValueError:
                    logger.error("Invalid algorithm %s for SHAKE, skip", _algo)
                    continue
                rd |= test_digest(
                    getattr(shake_wrapper, function), algo, Orientation.BYTE
                )
            case ["CC", "SHAKE", _algo, "digest", "bit"]:
                logger.info("Found CC_SHAKE function %s", function)
                try:
                    algo = Algorithm(f"SHAKE{_algo}")
                except ValueError:
                    logger.error("Invalid algorithm %s for SHAKE, skip", _algo)
                    continue
                rd |= test_digest(
                    getattr(shake_wrapper, function), algo, Orientation.BIT
                )
            case ["CC", "SHAKE", *_]:
                logger.warning("Ignored unknown CC_SHAKE function %s", function)
                continue
            case _:
                pass

    return rd


# --------------------------- Lib hook functions --------------------------------------


def _test_lib_digest(
    ffi: cffi.FFI, lib, function: str, algorithm: Algorithm, orientation: Orientation
) -> ResultsDict:
    """Tests a harness digest.

    Returns:
        The dictionary of results returned by :func:`test_digest`.
    """
    logger.info("Testing harness function %s", function)

    ffi.cdef(
        f"""int {function}(uint8_t *digest, size_t digest_size,
                        const uint8_t *input, size_t input_size);"""
    )
    shake = getattr(lib, function)

    def _shake(data: bytes, output_length: int) -> bytes:
        _data = ffi.new(f"uint8_t[{len(data)}]", data)
        buf = ffi.new(f"uint8_t[{output_length}]")
        retval = shake(buf, output_length, _data, len(data))
        if retval != 0:
            raise ValueError(f"{function} returned {retval}")
        return bytes(buf)

    return test_digest(_shake, algorithm, orientation)


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
            A list of CC_SHAKE functions to test.
        compliance:
            Whether to use compliance test vectors.
        resilience:
            Whether to use resilience test vectors.
    """
    logger.info("Found harness functions %s", ", ".join(functions))

    rd = ResultsDict()

    for function in functions:
        match function.split("_"):
            case ["CC", "SHAKE", bits, "digest"]:
                if bits == "128":
                    algorithm = Algorithm.SHAKE128
                elif bits == "256":
                    algorithm = Algorithm.SHAKE256
                else:
                    logger.error("Invalid value for SHAKE security level: %s", bits)
                    logger.warning("Ignoring function %s", function)
                    continue
                orientation = Orientation.BYTE
            case ["CC", "SHAKE", bits, "digest", "bit"]:
                if bits == "128":
                    algorithm = Algorithm.SHAKE128
                elif bits == "256":
                    algorithm = Algorithm.SHAKE256
                else:
                    logger.error("Invalid value for SHAKE security level: %s", bits)
                    logger.warning("Ignoring function %s", function)
                    continue
                orientation = Orientation.BIT
            case _:
                logger.debug("Ignoring unknown CC_SHAKE function %s", function)
        rd |= _test_lib_digest(ffi, lib, function, algorithm, orientation)

    return rd
