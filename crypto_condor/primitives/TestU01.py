"""Module for interacting with TestU01.

This module provides the :func:`test_file` function to test a file of random data using
the NIST battery of tests implemented by TestU01.

A modified version of TestU01 is bundled with |cc|, which adds the NIST battery from the
existing tests. This version has to compiled and installed locally: it requires make and
gcc to compile. Installation is done with :func:`install_testu01`, which should be
called by any function in this module that uses TestU01.
"""

import logging
import os
import shutil
import subprocess
from importlib import resources
from pathlib import Path

import attrs
from rich.progress import Progress

from crypto_condor.primitives.common import (
    DebugInfo,
    Results,
    TestType,
    get_appdata_dir,
)

# Module

logger = logging.getLogger(__name__)

# Data classes


@attrs.frozen
class TestU01Data:
    """Stores test result data.

    Args:
        info: Common debug info, see :class:`crypto_condor.primitives.common.DebugInfo`.
        name: The name of the test.
        pvalue: The resulting p-value.
    """

    info: DebugInfo
    name: str
    pvalue: float

    def __str__(self):
        """Returns a user-friendly representation."""
        s = str(self.info)
        s += f"Name = {self.name}\n"
        s += f"p-value = {self.pvalue}\n"
        return s


# Internal functions


def get_testu01_dir() -> Path:
    """Returns the installation path of TestU01."""
    return get_appdata_dir() / "testu01"


def install_testu01(*, debug: bool = False):
    """Installs TestU01.

    Checks if the path returned by :func:`get_testu01_dir` exists. If not, copies the
    necessary files to that path. It then checks whether TestU01 is compiled, and
    compiles it if not.

    Keyword Args:
        debug: If True, the compilation output is not captured by subprocess, displaying
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
            logger.error("Could not compile TestU01")
            if logger.getEffectiveLevel() > logging.DEBUG:
                logger.warning(
                    (
                        "To see the compilation output,"
                        " increase the verbosity with crypto-condor-cli -vv ..."
                    )
                )
            raise


# Test functions


def test_file(filename: str, *, bit_count: int = 0) -> Results | None:
    """Tests the output of a PRNG using TestU01.

    Args:
        filename: The name of the file to test.

    Keyword Args:
        bit_count: The number of bits to read, must be less or equal to the size of the
            file.

    Returns:
        The results obtained from testing the file, None if the test could not be run
        (e.g. compilation error).
    """
    # Check that TestU01 is already installed.
    try:
        install_testu01()
    except subprocess.CalledProcessError:
        logger.exception("Can't run TestU01, compilation failed")
        return None

    t_dir = get_testu01_dir()
    testu01 = t_dir / "testu01.sh"

    file = Path(filename).absolute()
    args = [str(testu01), str(file)]

    if bit_count > 0:
        args += [str(bit_count)]

    try:
        output = subprocess.check_output(args, cwd=t_dir, text=True)
    except subprocess.CalledProcessError as error:
        logger.error("Error running TestU01")
        logger.debug(error)
        logger.debug(error.stdout)
        logger.debug(error.stderr)
        return None

    lines = output.split("\n")

    # Example:
    # Size: 1600000 bytes = 12800000 bits
    parts = lines[0].split(" = ")
    n_bits = int(parts[1].split(" ")[0])

    results = Results(
        "TestU01",
        "test_file",
        "Tests the output of a PRNG with TestU01.",
        {"filename": filename, "bit_count": bit_count if bit_count else n_bits},
    )
    results.add_notes({"TestU01": "TestU01 test"})

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

    for tid, line in enumerate(lines[13:]):
        if line.startswith(" ---"):
            break

        info = DebugInfo(tid, TestType.VALID, ["TestU01"])

        # test_id = int(line[0:3].lstrip())
        test_name = line[5:55].rstrip()

        if "NOT IMPLEMENTED" in line:
            # Currently omitting NOT IMPLEMENTED tests from the results.
            # results.add(tid, True, TestType.VALID, comment=test_name, flag="TestU01")
            continue

        if line[56:60] == "PASS":
            info.result = True

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

        data = TestU01Data(info, test_name, test_pvalue)
        results.add(data)

    return results


# Block to install TestU01 by running the module as a script.
if __name__ == "__main__":
    install_testu01(debug=True)
