"""Module to test a shared library harness.

|cc| can test functions exposed by a shared library, on the condition that these
functions follow the naming convention and signature described by the **shared library
API**. To use this mode, this module provides the :func:`test_lib` function.
"""

import importlib
import inspect
import logging
from collections import defaultdict
from pathlib import Path
from typing import Callable

import _cffi_backend
import cffi
import lief

from crypto_condor.constants import SUPPORTED_PRIMITIVES
from crypto_condor.primitives.common import ResultsDict, _load_python_harness

logger = logging.getLogger(__name__)


# -------------------------------------------------------------------------------------
# Utils
# -------------------------------------------------------------------------------------


def list_functions(
    harness: Path, included: list[str], excluded: list[str]
) -> dict[str, list[str]]:
    """Lists functions in a harness.

    Args:
        harness:
            A path to the harness to explore.
        included:
            A list of functions to test ('included'). Can be empty, in which case all
            functions that start with ``CC_`` are included.
        excluded:
            A list of functions to exclude. Can be empty.

    Returns:
        A dictionary, where values are list of function names. Three keys are fixed:
        ``included``, for all included functions regardless of primitive, ``excluded``
        for all excluded functions, and ``other`` for any function that does not start
        with ``CC_``. Additionally, each primitive that has at least one function
        included has its own entry.

    Notes:
        The duplication of function names in ``included`` and the per-primitive lists is
        intentional. The idea is to avoid another for-loop in :func:`test_harness` to
        group functions by primitive.
    """
    lief_lib = lief.parse(harness.read_bytes())
    if lief_lib is None:
        raise ValueError("Could not parse the harness with LIEF")
    functions: dict[str, list[str]] = defaultdict(list)

    for name in set(
        [
            func.name
            for func in lief_lib.exported_functions  # type: ignore
            if isinstance(func.name, str)
        ]
    ):
        if name.startswith("CC_"):
            if name in excluded or (included and name not in included):
                logger.debug("Excluded %s", name)
                functions["excluded"].append(name)
            else:
                logger.debug("Found included function %s", name)
                primitive = name.split("_")[1]
                functions[primitive].append(name)
                functions["included"].append(name)
        else:
            functions["other"].append(name)

    return functions


def list_functions_lib(harness: Path) -> list[str]:
    """Lists all functions from a shared lib that look like harness functions.

    It lists all functions starting with ``CC_`` and a valid primitive. Uses :mod:`lief`
    to parse the symbols.

    Args:
        harness:
            A path to a shared lib file.

    Returns:
        A list of function names.
    """
    functions = []

    lief_lib = lief.parse(harness.read_bytes())
    if lief_lib is None:
        return functions

    for name in set(
        [
            func.name
            for func in lief_lib.exported_functions  # type: ignore
            if isinstance(func.name, str)
        ]
    ):
        try:
            prefix, primitive, *_ = name.split("_")
        except ValueError:
            continue
        if prefix == "CC" and primitive in SUPPORTED_PRIMITIVES:
            functions.append(name)

    return functions


def list_functions_python(harness: Path) -> list[str]:
    """Lists all functions from a Python file that look like harness functions.

    It lists all functions starting with ``CC_`` and a valid primitive. The current
    strategy is to load the harness as it would be for testing.

    Args:
        harness:
            A path to a Python file.

    Returns:
        A list of function names.
    """
    functions = []

    if (loaded_harness := _load_python_harness(harness)) is None:
        return functions

    for name, _ in inspect.getmembers(loaded_harness, inspect.isfunction):
        try:
            prefix, primitive, *_ = name.split("_")
        except ValueError:
            continue
        if prefix == "CC" and primitive in SUPPORTED_PRIMITIVES:
            functions.append(name)

    return functions


def list_files(rootdir: Path) -> list[Path]:
    """Recursively finds all ``cctest`` files in a directory."""
    return list(rootdir.glob("**/cctest_*.py")) + list(rootdir.glob("**/cctest_*.so"))


# -------------------------------------------------------------------------------------
# C harness
# -------------------------------------------------------------------------------------


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

        >>> from crypto_condor import harness
        >>> from pathlib import Path
        >>> my_lib = Path("libtest.so")
        >>> results = harness.test_lib(my_lib)

        This tests *all* CC functions found. Sometimes it may be useful to limit which
        functions are tested, e.g. when testing one primitive with several parameters.
        We can use the ``included`` and ``excluded`` arguments:

        >>> # To only test CC_SHA_256_digest
        >>> results = harness.test_lib(my_lib, included=["CC_SHA_256_digest"])
        >>> # To test all functions *except* CC_SHA_256_digest
        >>> results = harness.test_lib(my_lib, excluded=["CC_SHA_256_digest"])
    """
    if not harness.is_file():
        raise FileNotFoundError(f"No shared library named {str(harness)} found")
    if harness.suffix not in {".so", ".dylib"}:
        raise ValueError(
            "File is not a shared library, please supply a .so or .dylib file"
        )

    if included is None:
        included = []
    if excluded is None:
        excluded = []

    results = ResultsDict()

    functions = list_functions(harness, included, excluded)

    # Check that at least one CC functions was found, even if excluded.
    if len(functions["included"]) == 0 and len(functions["excluded"]) == 0:
        logger.error("No CC functions found in this harness")
        return results

    # Check if 'included' functions were not found.
    diff = set(included).difference(set(functions["included"]))
    if len(diff) > 0:
        logger.warning(
            "The following 'included' functions were not found in this harness: %s",
            ", ".join(diff),
        )

    # Lastly check if there are actually 'included' functions.
    if len(functions["included"]) == 0:
        logger.error("No 'included' functions found in this harness")
        return results

    logger.debug("dlopen %s", str(harness))
    ffi = cffi.FFI()
    lib = ffi.dlopen(str(harness.absolute()))

    # Dynamically determine the module to import, call its test_lib function.
    test: Callable[[cffi.FFI, _cffi_backend.Lib, list[str], bool, bool], ResultsDict]
    for prim_name, prim_funcs in functions.items():
        if prim_name in {"included", "excluded", "other"}:
            continue
        module = importlib.import_module(f"crypto_condor.primitives.{prim_name}")
        test = module.test_lib
        try:
            results |= test(ffi, lib, prim_funcs, compliance, resilience)
        except ValueError as error:
            logging.error("Error running CC_%s functions: %s", prim_name, str(error))

    return results


# -------------------------------------------------------------------------------------
# Python harness
# -------------------------------------------------------------------------------------


def test_python_harness(file: Path, compliance: bool, resilience: bool) -> ResultsDict:
    """FIXME."""
    results = ResultsDict()
    harness = _load_python_harness(file)

    primitives: set[str] = set()

    for name, _ in inspect.getmembers(harness, inspect.isfunction):
        match name.split("_"):
            case ["CC", primitive, *_]:
                primitives.add(primitive)

    for primitive in primitives:
        try:
            module = importlib.import_module(f"crypto_condor.primitives.{primitive}")
            results |= module.test_harness_python(file, compliance, resilience)
        except ModuleNotFoundError:
            logger.error(f"No primitive {primitive}")
        except Exception:
            logger.exception("Caught exception")

    return results


# -------------------------------------------------------------------------------------
# Auto-discovery
# -------------------------------------------------------------------------------------


def test_dir(
    rootdir: Path, compliance: bool, resilience: bool
) -> list[tuple[Path, ResultsDict]]:
    list_results = list()
    files = list_files(rootdir)
    for file in files:
        if file.suffix == ".py":
            results = test_python_harness(file, compliance, resilience)
        elif file.suffix == ".so":
            results = test_harness(file, compliance=compliance, resilience=resilience)
        list_results += [(file, results)]
    return list_results
