"""Module to test SHAKE implementations."""

import importlib
import logging
import sys
from pathlib import Path
from typing import Protocol

import attrs
import strenum
from rich.progress import track

from crypto_condor.primitives.common import Results, ResultsDict, TestInfo, TestType
from crypto_condor.vectors.SHAKE import Algorithm, Orientation, ShakeVectors

logger = logging.getLogger(__name__)


def __dir__():  # pragma: no cover
    return [
        # Enums
        Wrapper.__name__,
        # Protocols
        Xof.__name__,
        # Functions
        test.__name__,
        run_wrapper.__name__,
        # Imported
        Orientation.__name__,
        Algorithm.__name__,
    ]


# --------------------------- Enums ---------------------------------------------------


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


def test(xof: Xof, xof_algorithm: Algorithm, orientation: Orientation) -> ResultsDict:
    """Tests a SHAKE implementation.

    Runs NIST test vectors on the given function. The function to test must conform to
    the :protocol:`Xof` protocol.

    Args:
        xof: The function to test.
        xof_algorithm: The algorithm of the XOF to test.
        orientation: The orientation of the implementation, either bit- or
            byte-oriented.

    Returns:
        A :class:`ResultsDict` containing the results of short message (``short``), long
        message (``long``), Monte-Carlo (``monte-carlo``), and variable length
        (``variable``) tests. The keys are ``SHAKE/<algorithm>/<type>``.
    """
    vectors = ShakeVectors.load(xof_algorithm, orientation)

    short_results = Results(
        "SHA",
        "test_shake",
        "NIST short message vectors",
        {"xof_algorithm": xof_algorithm, "orientation": orientation},
    )
    long_results = Results(
        "SHA",
        "test_shake",
        "NIST long message vectors",
        {"xof_algorithm": xof_algorithm, "orientation": orientation},
    )
    mc_results = Results(
        "SHA",
        "test_shake",
        "NIST Monte-Carlo vectors",
        {"xof_algorithm": xof_algorithm, "orientation": orientation},
    )
    var_results = Results(
        "SHA",
        "test_shake",
        "NIST Variable length vectors",
        {"xof_algorithm": xof_algorithm, "orientation": orientation},
    )

    for tid, test in track(
        enumerate(vectors.short_msg.tests, start=1), "[NIST] short message vectors"
    ):
        info = TestInfo.new(tid, TestType.VALID, ["Compliance"])
        data = ShakeData(test.msg, test.output)
        try:
            output = xof(test.msg, len(test.output))
        except Exception as error:
            info.fail(f"Digest failed: {str(error)}", data)
            logger.debug("Digest failed", exc_info=True)
            short_results.add(info)
            continue
        data.result = output
        if output == test.output:
            info.ok(data)
        else:
            info.fail("Wrong digest", data)
        short_results.add(info)

    for tid, test in track(
        enumerate(vectors.long_msg.tests, start=1),
        "[NIST] short message vectors",
    ):
        info = TestInfo.new(tid, TestType.VALID, ["Compliance"])
        data = ShakeData(test.msg, test.output)
        try:
            output = xof(test.msg, len(test.output))
        except Exception as error:
            info.fail(f"Digest failed: {str(error)}", data)
            logger.debug("Digest failed", exc_info=True)
            long_results.add(info)
            continue
        data.result = output
        if output == test.output:
            info.ok(data)
        else:
            info.fail("Wrong digest", data)
        long_results.add(info)

    # Monte-Carlo vectors.
    mv = vectors.montecarlo
    # Start with the 'seed' message.
    output = mv.msg
    # max_len and min_len are lengths in bytes.
    max_len = (mv.max_len + 7) // 8
    min_len = (mv.min_len + 7) // 8
    # Start with max_len.
    output_len = max_len
    res = True
    for j in track(range(100), "[NIST] Monte-Carlo vectors"):
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
    mc_info = TestInfo.new(1, TestType.VALID, ["Compliance"])
    mc_data = ShakeMcData(mv.msg)
    if res:
        mc_info.ok(mc_data)
    else:
        mc_info.fail(f"Failed at checkpoint {j}", mc_data)
    mc_results.add(mc_info)

    # Variable vectors.
    for tid, test in track(
        enumerate(vectors.variable.tests, start=1), "[NIST] Variable length vectors"
    ):
        info = TestInfo.new(tid, TestType.VALID, ["Compliance"])
        data = ShakeData(test.msg, test.output)
        try:
            output = xof(test.msg, test.output_len // 8)
        except Exception as error:
            info.fail(f"Digest failed: {str(error)}", data)
            logger.debug("Digest failed", exc_info=True)
            var_results.add(info)
            continue
        data.result = output
        if output == test.output:
            info.ok(data)
        else:
            info.fail("Wrong digest", data)
        var_results.add(info)

    return ResultsDict(
        {
            f"SHAKE/test_shake/{str(xof_algorithm)}/short": short_results,
            f"SHAKE/test_shake/{str(xof_algorithm)}/long": long_results,
            f"SHAKE/test_shake/{str(xof_algorithm)}/monte_carlo": mc_results,
            f"SHAKE/test_shake/{str(xof_algorithm)}/variable": var_results,
        }
    )


def _run_shake_python_wrapper(algorithm: Algorithm, orientation: Orientation):
    """Runs the Python SHAKE wrapper.

    Args:
        algorithm:
            The XOF algorithm to test.
        orientation:
            The orientation of the implementation, either bit- or byte-oriented.
    """
    wrapper = Path.cwd() / "shake_wrapper.py"
    if not wrapper.is_file():
        raise FileNotFoundError("Can't find shake_wrapper.py in the current directory.")

    logger.info("Running Python SHAKE wrapper")

    # Add CWD to the path, at the beginning in case this is called more than once, since
    # the previous CWD would have priority.
    sys.path.insert(0, str(Path.cwd()))

    # Before importing the wrapper we check if it's already in the loaded modules, in
    # which case we want to reload it or we would be testing the wrapper loaded
    # previously.
    imported = "shake_wrapper" in sys.modules.keys()

    # Import it normally.
    try:
        shake_wrapper = importlib.import_module("shake_wrapper")
    except ModuleNotFoundError as error:
        logger.debug(error)
        raise FileNotFoundError("Can't load the wrapper!") from error

    # Then reload it if necessary.
    if imported:
        logger.debug("Reloading the SHAKE Python wrapper")
        shake_wrapper = importlib.reload(shake_wrapper)

    results_dict = test(shake_wrapper.shake, algorithm, orientation)

    # To de-clutter the path, remove the CWD.
    sys.path.remove(str(Path.cwd()))

    return results_dict


def run_wrapper(
    language: Wrapper, xof_algorithm: Algorithm, orientation: Orientation
) -> ResultsDict:
    """Runs the corresponding wrapper.

    Args:
        language:
            The language of the wrapper to run.
        xof_algorithm:
            The algorithm of the XOF to test.
        orientation:
            The orientation of the implementation, either bit- or byte-oriented.
    """
    match language:
        case Wrapper.PYTHON:
            return _run_shake_python_wrapper(xof_algorithm, orientation)
        case _:  # pragma: no cover (mypy)
            raise ValueError
