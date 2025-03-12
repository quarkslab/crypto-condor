"""Module to test a shared library harness.

|cc| can test functions exposed by a shared library, on the condition that these
functions follow the naming convention and signature described by the **shared library
API**. To use this mode, this module provides the :func:`test_lib` function.
"""

import importlib
import logging
from collections import defaultdict
from pathlib import Path
from typing import Callable

import _cffi_backend
import cffi
import lief

from crypto_condor.primitives.common import ResultsDict

# --------------------------- Module --------------------------------------------------
logger = logging.getLogger(__name__)


# --------------------------- Functions -----------------------------------------------
def test_harness(
    harness: Path,
    included: list[str] | None = None,
    excluded: list[str] | None = None,
    compliance: bool = True,
    resilience: bool = False,
) -> ResultsDict:
    """Tests a shared library harness.

    It loads the library and searches for functions that follow the naming convention.
    If there are any, they are passed to the corresponding primitive module's
    ``test_lib`` function.

    Args:
        harness:
            The path to the shared library harness.

    Keyword Args:
        included:
            List of included functions, allow-list style.
        excluded:
            List of excluded functions, deny-list style.
        compliance:
            Whether to use compliance test vectors.
        resilience:
            Whether to use resilience test vectors.

    Returns:
        A dictionary of all results returned by the different primitives called.

    Example:
        The simplest usage is to pass the path to the shared library.

        >>> from crypto_condor import shared_library
        >>> from pathlib import Path
        >>> my_lib = Path("libtest.so")
        >>> results = shared_library.test_lib(my_lib)

        This tests *all* CC functions found. Sometimes it may be useful to limit which
        functions are tested, e.g. when testing one primitive with several parameters.
        We can use the ``included`` and ``excluded`` arguments:

        >>> # To only test CC_SHA_256_digest
        >>> results = shared_library.test_lib(my_lib, included=["CC_SHA_256_digest"])
        >>> # To test all functions *except* CC_SHA_256_digest
        >>> results = shared_library.test_lib(my_lib, excluded=["CC_SHA_256_digest"])
    """
    if not harness.is_file():
        raise FileNotFoundError(f"No shared library named {str(harness)} found")

    if included is None:
        included = []
    if excluded is None:
        excluded = []

    lief_lib = lief.parse(harness.read_bytes())
    if lief_lib is None:
        raise ValueError("Could not parse the harness with LIEF")

    primitives: dict[str, list[str]] = defaultdict(list)

    for funcname in set([func.name for func in lief_lib.exported_functions]):
        if isinstance(funcname, bytes):
            logger.debug("Function name is in bytes, skipped")
            continue
        match funcname.split("_"):
            case ["CC", primitive, *_]:
                # TODO: test if primitive is supported and supports this mode.
                if funcname in excluded or (included and funcname not in included):
                    logger.info("Excluded %s", funcname)
                    continue
                primitives[primitive].append(funcname)
                logger.debug("Found CC function %s", funcname)
            case _:
                logger.debug("Omitted function %s", funcname)
                continue

    logger.debug("dlopen %s", str(harness))
    ffi = cffi.FFI()
    lib = ffi.dlopen(str(harness.absolute()))

    results = ResultsDict()

    # Dynamically determine the module to import, call its test_lib function.
    test: Callable[[cffi.FFI, _cffi_backend.Lib, list[str], bool, bool], ResultsDict]
    for primitive, functions in primitives.items():
        module = importlib.import_module(f"crypto_condor.primitives.{primitive}")
        test = module.test_lib
        try:
            results |= test(ffi, lib, functions, compliance, resilience)
        except ValueError as error:
            logging.error("Error running CC_%s functions: %s", primitive, str(error))

    return results
