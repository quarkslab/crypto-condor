"""This module provides a high-level interface for TestU01.

`TestU01 <https://simul.iro.umontreal.ca/testu01/tu01.html>`_.
is a C library for empirical testing of random number generators. This module exposes
high-level methods for running the
`NIST battery of tests <https://csrc.nist.gov/Projects/random-bit-generation/Documentation-and-Software/Guide-to-the-Statistical-Tests>`_
using the tests implemented by TestU01. This battery is not implemented directly by
TestU01, |cc| comes bundled with a modified version that defines this battery.

Installation
------------

The library has to be compiled and installed locally. The installation requires:

* ``make``;
* a C compiler (``/usr/bin/cc`` by default, can be changed by setting the ``CC``
  environment variable).

The compilation of the library is done automatically when running any of the test
function below for the first time. Subsequent runs use the installed version.

For manual installation, see :func:`install_testu01`.

A modified version of TestU01 is bundled with |cc|, which adds the NIST battery from the
existing tests. This version has to compiled and installed locally: it requires ``make``
and a C compiler (``/usr/bin/cc`` by default, set the ``CC`` environment variable to
chose another one). The compilation is done automatically when running any of the tests
for the first time.

Manual installation is done with :func:`install_testu01`, which should be called by any
function in this module that uses TestU01.

.. important::

   In general you should not need to use these functions: they are called whenever a
   test involving TestU01 is executed. If the compilation fails, you can `open an issue
   <https://github.com/quarkslab/crypto-condor/issues>`_.

.. autofunction:: get_testu01_dir

.. autofunction:: install_testu01


How much data to generate?
--------------------------

As a general rule, more data means the tests are more likely to fail if the output is
not uniformly random. Additionally, some tests will not run if the sample size is too
small. 100KB enables 27 out of 29 available tests: as such, all functions in this module
enforce 100KB as the minimum size to generate. The default, and recommended minimum, is
10MB, which enables all 29 tests.

Test an RNG
-----------

.. autofunction:: test_file

.. autofunction:: test_generator

.. autofunction:: test_raw

Protocols
---------

.. autoprotocol:: Generator
"""

import logging
import os
import shutil
import subprocess
import tempfile
from importlib import resources
from math import ceil
from pathlib import Path
from typing import Protocol

import attrs
from rich.progress import Progress

from crypto_condor.primitives.common import (
    Results,
    ResultsDict,
    TestInfo,
    TestType,
    get_appdata_dir,
)

# -------------------------------------------------------------------------------------
# Module variables
# -------------------------------------------------------------------------------------

logger = logging.getLogger(__name__)

# -------------------------------------------------------------------------------------
# Dataclasses
# -------------------------------------------------------------------------------------


@attrs.frozen
class TestU01Data:
    """Stores test result data.

    Args:
        name: The name of the test.
        pvalue: The resulting p-value.
    """

    name: str
    pvalue: float

    def __str__(self):
        """Returns a user-friendly representation."""
        return f"""Name = {self.name}
p-value: {self.pvalue}
"""


# -------------------------------------------------------------------------------------
# Protocols
# -------------------------------------------------------------------------------------


class Generator(Protocol):
    """Represents a random number generator."""

    def __call__(self) -> bytes:
        """Generates a random number.

        Returns:
            A random number encoded as bytes. All values returned by this function must
            have the same length in bytes.
        """
        ...  # pragma: no cover


# -------------------------------------------------------------------------------------
# Internal functions
# -------------------------------------------------------------------------------------


def get_testu01_dir() -> Path:
    """Returns the installation path of TestU01."""
    return get_appdata_dir() / "testu01"


def install_testu01(*, debug: bool = False):
    """Installs TestU01.

    Checks if the path returned by :func:`get_testu01_dir` exists. If not, copies the
    necessary files to that path. It then checks whether TestU01 is compiled, and
    compiles it if not.

    Keyword Args:
        debug:
            If True, the compilation output is not captured by subprocess, displaying
            the full output on stdout.
    """
    t_dir = get_testu01_dir()

    if not t_dir.is_dir():
        logger.warning("TestU01 directory not found, copying it to %s", str(t_dir))
        t01 = resources.files("crypto_condor") / "primitives/_testu01"
        try:
            shutil.copytree(str(t01), t_dir)
        except Exception:
            logger.exception("Could not copy TestU01 source")
            raise

    t_exec = t_dir / "examples/nist"
    if t_exec.is_file():
        return

    make = t_dir / "qbmake.sh"

    with Progress() as progress:
        # Show subprocess output (i.e. do not capture output) if in debug or in CI.
        capture_output = not (
            debug
            or bool(os.environ.get("GITHUB_ACTIONS", False))
            or logger.getEffectiveLevel() <= logging.DEBUG
        )
        task = progress.add_task(
            "Compiling TestU01, please wait", total=None, visible=capture_output
        )
        try:
            _ = subprocess.run(
                [str(make)],
                cwd=t_dir,
                capture_output=capture_output,
                text=True,
                check=True,
                timeout=300,
            )
            progress.update(task, completed=True)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            logger.exception("Could not compile TestU01")
            raise


# -------------------------------------------------------------------------------------
# Test functions
# -------------------------------------------------------------------------------------


# NOTE for developers: all tests have to ensure that TestU01 is installed by calling
# install_testu01(). In practice, since test_file() calls install_testu01() and
# implements the call to TestU01, tests that depend on test_file() can skip this
# requirement.


def test_file(filename: str, *, bit_count: int = 0) -> ResultsDict:
    """Tests the output of a random number generator written to a file.

    Args:
        filename:
            The name of the file to test. It must be 100KB at minimum.

    Keyword Args:
        bit_count:
            This argument is ignored, the entire file will be read.

    Returns:
        A dictionary of results, containing a single :class:`Results` with the results
        of all TestU01 tests.

    Raises:
        ValueError:
            If the file is smaller than 100KB.

    .. versionchanged:: 2025.03.12
        ``test_file`` now returns `ResultsDict` containing a single `Results` for a
        TestU01 run.
    .. versionchanged:: FIXME(version)
        ``bit_count`` is deprecated: the argument is ignored and will be removed in a
        later version.
    """
    file = Path(filename).absolute()
    fsize = file.stat().st_size
    if fsize < 100_000:
        raise ValueError(f"TestU01 requires at least 100 000 bytes, got {fsize}")

    results = ResultsDict()

    # Check that TestU01 is already installed.
    try:
        install_testu01()
    except subprocess.CalledProcessError:
        return rd

    t_dir = get_testu01_dir()
    testu01 = t_dir / "testu01.sh"
    args = [str(testu01), str(file)]
    try:
        output = subprocess.check_output(args, cwd=t_dir, text=True)
    except subprocess.CalledProcessError as error:
        logger.error("Error running TestU01: %s", error.stdout)
        return rd

    lines = output.split("\n")

    # Example:
    # Size: 1600000 bytes = 12800000 bits
    parts = lines[0].split(" = ")
    n_bits = int(parts[1].split(" ")[0])

    res = Results(
        "TestU01",
        "test_file",
        "Tests the output of a PRNG with TestU01.",
        {"file name": filename, "file size": fsize},
    )
    results.add(res)

    # The format works as follows:
    #  - A 1 or 2 digits numerical ID, right-padded to three characters.
    #  - Two whitespace characters.
    #  - The name of the test, left-padded to 50 characters.
    #  - A single whitespace.
    #  - The result of the test.
    #    - If the test is not yet implemented, the result is 'NOT IMPLEMENTED'.
    #    - Otherwise, the result is either PASS or FAIL, followed by the corresponding
    #      p-value. The p-value is a value between 0 and 1. It is displayed with 6
    #      decimal digits (0.123456), but can have an additional representation in
    #      scientific notation appended if necessary. There are four types:
    #        1. 0.000000  eps
    #        2. 0.999999 1 -  1.0e-6
    #        3. 0.000000  1.2e-7
    #        4. 0.987654  0.999

    tid = 0
    start = False

    for line in lines:
        if start and line.startswith(" ---"):
            break

        if not start:
            if line.startswith("     (PASS"):
                start = True
            continue

        # TODO: parse warnings.

        tid += 1
        info = TestInfo.new(tid, TestType.VALID, ["TestU01"])

        # test_id = int(line[0:3].lstrip())
        test_name = line[5:55].rstrip()

        if "NOT IMPLEMENTED" in line:
            # Currently omitting NOT IMPLEMENTED tests from the results.
            # results.add(tid, True, TestType.VALID, comment=test_name, flag="TestU01")
            continue

        pvalue = line[61:].rstrip()

        if "eps" in pvalue:
            # Case 1, p-value is less than eps, usually around 1e-300
            test_pvalue = 0.0
        else:
            lp, rp = pvalue[0:8], pvalue[8:].strip()
            if "e" in rp:
                if " - " in pvalue:
                    # Case 2, the right part is 1 minus something small. To preserve the
                    # accuracy we extract the rightmost part and subtract from 1.
                    rp = pvalue.split(" - ")[-1]
                    rp = rp.strip()
                    test_pvalue = 1.0 - float(rp)
                else:
                    # Case 3, we take the right part directly.
                    test_pvalue = float(rp)
            else:
                # Case 4, we take the left part as it may be more accurate.
                test_pvalue = float(lp)

        data = TestU01Data(test_name, test_pvalue)

        if "PASS" in line:
            info.ok(data)
        else:
            info.fail(data=data)

        res.add(info)

    return results


def test_raw(raw: bytes) -> ResultsDict:
    """Tests the output of a random number generator.

    Writes the output to a temporary file and runs TestU01 on it.

    Args:
        raw:
            The raw output to test. It must be at least 100 000 bytes long.

    Raises:
        ValueError:
            If the length of ``raw`` is less than 100 000 bytes.

    .. versionadded:: FIXME(version)
    """
    if len(raw) < 100_000:
        raise ValueError(f"At least 100 000 bytes required, got {len(raw)} bytes")

    results = ResultsDict()
    # Use tempfile because the caller is giving a string of bytes, so they can save it
    # to a file and use test_file() if storing the output is important.
    with tempfile.NamedTemporaryFile("wb") as file:
        written = file.write(raw)
        if written < len(raw):
            logger.error("Failed to write raw RNG output to file %s", file.name)
            return results
        results |= test_file(file.name)
    return results


def test_generator(
    gen: Generator, nbytes: int = 10_000_000, outfile: str = ""
) -> ResultsDict:
    """Tests a random number generator.

    Calls ``gen`` one time to determine the size of the output numbers, then calls
    ``gen`` to generate enough values to fill an array of ``nbytes``. This output is
    tested with TestU01.

    Any exceptions raised by ``gen`` are treated as unrecoverable errors and an empty
    :class:`ResultsDict` is returned.

    Args:
        gen:
            The random number generator. Must follow :protocol:`Generator`. Notably,
            this function expects all values returned by ``gen`` to have the same length
            in bytes.
        nbytes:
            The number of bytes to generate with ``gen``. Must be at least 100 000.
        outfile:
            Optional, the name of the file to save the generated output. If empty, the
            output is not saved.

    Returns:
        The results of the tests are included in one instance of :class:`Results`, in a
        :class:`ResultsDict`. The dictionary can be empty if an exception was raised by
        ``gen``.

    Raises:
        ValueError:
            If ``nbytes`` is less than 100 000.

    .. versionadded:: FIXME(version)
    """
    results = ResultsDict()

    if nbytes < 100_000:
        raise ValueError(f"At least 100 000 bytes required, got {nbytes} bytes")

    try:
        outlen = len(gen())
    except Exception:
        logger.exception("Failed to call random generator")
        return results

    output = bytes()

    n = ceil(nbytes / outlen)
    for _ in range(n):
        try:
            out = gen()
        except Exception:
            logger.exception("Failed to call random generator")
            return results
        else:
            output += out

    if outfile:
        with open(outfile, "wb") as file:
            file.write(output)
        return test_file(outfile)
    else:
        return test_raw(output)


# Install TestU01 when running the module as a script.
if __name__ == "__main__":
    install_testu01(debug=True)
