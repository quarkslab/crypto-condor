"""Module for HQC."""

import importlib
import inspect
import json
import logging
import sys
from pathlib import Path
from typing import Protocol

import attrs
import cffi
import strenum
from rich.progress import track

from crypto_condor.primitives.common import Results, ResultsDict, TestInfo, TestType
from crypto_condor.vectors._hqc.hqc_pb2 import HqcTest, HqcVectors
from crypto_condor.vectors.hqc import Paramset

# --------------------------- Module --------------------------------------------------

logger = logging.getLogger(__name__)


def __dir__():  # pragma: no cover
    return [
        # Enums
        Wrapper.__name__,
        # Protocols
        Encaps.__name__,
        Decaps.__name__,
        # Test functions
        test_decaps.__name__,
        test_invariant.__name__,
        test_lib.__name__,
        # Runners
        test_wrapper.__name__,
        test_wrapper_python.__name__,
        # Imported
        Paramset.__name__,
    ]


# --------------------------- Enums ---------------------------------------------------


class Wrapper(strenum.StrEnum):
    """Supported languages for wrappers."""

    PYTHON = "Python"


# --------------------------- Vectors -------------------------------------------------


def _load_vectors(
    paramset: Paramset, compliance: bool, resilience: bool
) -> list[HqcVectors]:
    """Loads vectors for a given parameter set.

    Args:
        paramset:
            The parameter set to load vectors of.
        compliance:
            If True, loads compliance test vectors.
        resilience:
            If True, loads resilience test vectors.

    Returns:
        A list of vectors, can be empty.
    """
    vectors_dir = importlib.resources.files("crypto_condor") / "vectors/_hqc"
    vectors = list()

    sources_file = vectors_dir / "hqc.json"
    with sources_file.open("r") as file:
        sources = json.load(file)

    for filename in sources.get(str(paramset)):
        vectors_file = vectors_dir / "pb2" / filename
        _vec = HqcVectors()
        logger.debug("Loading HQC vectors from %s", str(filename))
        try:
            _vec.ParseFromString(vectors_file.read_bytes())
        except Exception:
            logger.exception("Failed to load HQC vectors from %s", str(filename))
        if compliance and _vec.compliance:
            vectors.append(_vec)
        if resilience and not _vec.compliance:
            vectors.append(_vec)

    return vectors


# --------------------------- Protocols -----------------------------------------------


class Encaps(Protocol):
    """Represents an HQC encapsulation function."""

    def __call__(self, pk: bytes) -> tuple[bytes, bytes]:
        """Generates and encapsulates a shared secret.

        Args:
            pk:
                The public key to encapsulate the secret with.

        Returns:
            A tuple (ct, ss) containing the shared secret (ss) and ciphertext (ct).
        """
        ...


class Decaps(Protocol):
    """Represents an HQC decapsulation function."""

    def __call__(self, sk: bytes, ct: bytes) -> bytes:
        """Decapsulates a shared secret.

        Args:
            sk:
                The secret key to use.
            ct:
                The ciphertext to decapsulate.

        Returns:
            The decapsulated shared secret.
        """
        ...


# --------------------------- Dataclasses----------------------------------------------


@attrs.define
class DecData:
    """Debug data for :func:`test_decaps`."""

    sk: bytes
    ct: bytes
    ss: bytes
    ret_ss: bytes | None = None

    def __str__(self) -> str:
        """Returns a string representation of the fields in use."""
        return f"""sk = {self.sk.hex()}
ct = {self.ct.hex()}
ss = {self.ss.hex()}
ret_ss = {self.ret_ss.hex() if self.ret_ss is not None else "<none>"}
"""

    @classmethod
    def from_test(cls, test: HqcTest):
        """Creates a new instance from a test."""
        return cls(test.sk, test.ct, test.ss)


@attrs.define
class EncDecData:
    """Debug data for HQC tests."""

    pk: bytes
    sk: bytes
    ret_ct: bytes | None = None
    ret_ss_pk: bytes | None = None
    ret_ss_sk: bytes | None = None

    def __str__(self):
        """Returns a string representation of the fields in use."""
        return f"""pk = {self.pk.hex()}
sk = {self.sk.hex()}
ret_ct = {self.ret_ct.hex() if self.ret_ct is not None else "<none>"}
ret_ss_pk = {self.ret_ss_pk.hex() if self.ret_ss_pk is not None else "<none>"}
ret_ss_sk = {self.ret_ss_sk.hex() if self.ret_ss_sk is not None else "<none>"}
"""

    @classmethod
    def from_test(cls, test: HqcTest):
        """Creates a new instance from a test."""
        return cls(test.pk, test.sk)


# --------------------------- Test functions ------------------------------------------


def test_decaps(
    decaps: Decaps,
    paramset: Paramset,
    *,
    compliance: bool = True,
    resilience: bool = False,
) -> ResultsDict:
    """Tests decapsulation.

    Uses the given function to decapsulate ciphertexts and compares the resulting shared
    secret with the test vectors. The test passes if the secrets match.

    Args:
        decaps:
            The decapsulation function.
        paramset:
            The parameter set to use.

    Keyword Args:
        compliance:
            Whether to use compliance test vectors.
        resilience:
            Whether to use resilience test vectors.

    Returns:
        A dictionary of results, with one :class:`Results` per test vectors file.
    """
    rd = ResultsDict()
    all_vectors = _load_vectors(paramset, compliance, resilience)
    if not all_vectors:
        # TODO: more detailed warning (e.g. suggest using resilience).
        logger.warning("No test vectors found for %s")
        return rd

    test: HqcTest
    for vectors in all_vectors:
        res = Results.new("Test HQC decapsulation", ["paramset"])
        res.add_notes(vectors.notes)
        rd.add(res, extra_values=[vectors.source])

        for test in track(
            vectors.tests, rf"\[{paramset}]\[{vectors.source}] Test decaps"
        ):
            info = TestInfo.new_from_test(test, vectors.compliance)
            data = DecData.from_test(test)

            try:
                ret_ss = decaps(test.sk, test.ct)
            except NotImplementedError:
                logger.warning("%s decaps not implemented, test stopped", str(paramset))
                return rd
            except Exception as error:
                logger.debug("Caught an exception", exc_info=True)
                info.fail(f"Exception caught: {str(error)}", data)
                res.add(info)
                continue

            data.ret_ss = ret_ss
            same_ss = ret_ss == test.ss
            match (test.type, same_ss):
                case (TestType.VALID, True):
                    info.ok(data)
                case (TestType.VALID, False):
                    info.fail("Wrong shared secret", data)
                case _:
                    raise ValueError(
                        f"Invalid test type {test.type} and result {same_ss}"
                    )
            res.add(info)

    return rd


def test_invariant(encaps: Encaps, decaps: Decaps, paramset: Paramset) -> ResultsDict:
    """Tests the encapsulate then decapsulate invariant.

    Encapsulating to a public key then decapsulating with the corresponding secret key
    should always yield the same share secret. To test this invariant, crypto-condor
    uses key pairs from test vectors to perform both operations. The test passes if the
    shared secrets match.

    Args:
        encaps:
            The encapsulation function.
        decaps:
            The decapsulation function.
        paramset:
            The parameter set to test.

    Returns:
        A dictionary of results with one :class:`Results` per test vectors file.

    Notes:
        Only valid keys from compliance test vectors are used.
    """
    # Normally this does not require checking if there vectors, as we should always have
    # compliance test vectors for all parameter sets.
    all_vectors = _load_vectors(paramset, True, False)
    rd = ResultsDict()

    test: HqcTest
    for vectors in all_vectors:
        res = Results.new("Test HQC encapsulation and decapsulation", ["paramset"])
        res.add_notes(vectors.notes)
        rd.add(res, extra_values=[vectors.source])

        for test in track(
            vectors.tests, rf"\[{paramset}]\[{vectors.source}] Test invariant"
        ):
            if test.type != TestType.VALID:
                continue
            info = TestInfo.new_from_test(test, vectors.compliance)
            data = EncDecData.from_test(test)

            try:
                ret = encaps(test.pk)
            except NotImplementedError:
                logger.warning("%s encaps not implemented, test stopped", str(paramset))
                return rd
            except Exception as error:
                logger.debug("Caught an exception", exc_info=True)
                info.fail(f"Exception caught: {str(error)}", data)
                res.add(info)
                continue

            match ret:
                case (bytes() as ret_ct, bytes() as ret_ss_pk):
                    pass
                case (a, b):
                    info.fail(
                        f"Expected two bytes objects, got ({type(a)}, {type(b)})", data
                    )
                    res.add(info)
                    continue
                case _:
                    info.fail(
                        f"Expected two bytes objects, got {len(ret)} objects", data
                    )
                    res.add(info)
                    continue

            data.ret_ct = ret_ct
            data.ret_ss_pk = ret_ss_pk

            try:
                ret_ss_sk = decaps(test.sk, ret_ct)
            except NotImplementedError:
                logger.warning("%s decaps not implemented, test stopped", str(paramset))
                return rd
            except Exception as error:
                logger.debug("Caught an exception", exc_info=True)
                info.fail(f"Exception caught: {str(error)}")
                res.add(info)
                continue

            data.ret_ss_sk = ret_ss_sk

            same_ss = ret_ss_pk == ret_ss_sk

            if same_ss:
                info.ok(data)
            else:
                info.fail("Different shared secrets", data)
            res.add(info)

    return rd


# --------------------------- Runners -------------------------------------------------


def test_wrapper_python(
    wrapper: Path, compliance: bool, resilience: bool
) -> ResultsDict:
    """Tests a Python wrapper.

    Args:
        wrapper:
            A path to the wrapper to test.
        compliance:
            Whether to use compliance test vectors.
        resilience:
            Whether to use resilience test vectors.
    """
    logger.info("Running Python HQC wrapper: '%s'", str(wrapper.name))
    sys.path.insert(0, str(wrapper.parent.absolute()))
    already_imported = wrapper.stem in sys.modules.keys()
    try:
        hqc_wrapper = importlib.import_module(wrapper.stem)
    except ModuleNotFoundError as error:
        logger.error("Can't import wrapper: '%s'", str(error))
        raise
    if already_imported:
        logger.debug("Reloading HQC wrapper: '%s'", wrapper.stem)
        hqc_wrapper = importlib.reload(hqc_wrapper)

    rd = ResultsDict()

    for func, _ in inspect.getmembers(hqc_wrapper, inspect.isfunction):
        match func.split("_"):
            case ["CC", "HQC", _, "encaps"]:
                logger.info("Found %s, currently ignored", func)
                continue
            case ["CC", "HQC", _pset, "decaps"]:
                logger.info("Found %s", func)
                try:
                    paramset = Paramset(f"HQC-{_pset}")
                except ValueError:
                    logger.error(
                        "Invalid parameter set %s for HQC, function skipped", _pset
                    )
                    continue
                decaps = getattr(hqc_wrapper, func)
                rd |= test_decaps(decaps, paramset)
            case ["CC", "HQC", _pset, "invariant"]:
                logger.info("Found CC_HQC function %s", func)
                try:
                    paramset = Paramset(f"HQC-{_pset}")
                except ValueError:
                    logger.error(
                        "Invalid parameter set %s for HQC, function skipped", _pset
                    )
                    continue
                encaps_name = f"CC_HQC_{_pset}_encaps"
                decaps_name = f"CC_HQC_{_pset}_decaps"
                encaps = getattr(hqc_wrapper, encaps_name, None)
                decaps = getattr(hqc_wrapper, decaps_name, None)
                if encaps is None:
                    logger.error(
                        "Did not find %s to test invariant, test skipped", encaps_name
                    )
                    continue
                if decaps is None:
                    logger.error(
                        "Did not find %s to test invariant, test skipped", decaps_name
                    )
                    continue
                rd |= test_invariant(encaps, decaps, paramset)
            case ["CC", "HQC", *_]:
                logger.warning("Ignored invalid function %s", func)
                continue
            case _:
                pass

    return rd


def test_wrapper(wrapper: Path, compliance: bool, resilience: bool) -> ResultsDict:
    """Tests an HQC wrapper.

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
    """
    if not wrapper.is_file():
        raise FileNotFoundError(f"Wrapper {str(wrapper)} not found")

    match wrapper.suffix:
        case ".py":
            return test_wrapper_python(wrapper, compliance, resilience)
        case _:
            raise ValueError(f"No runner for '{wrapper.suffix}' wrappers")


# --------------------------- Lib hook functions --------------------------------------


def _test_harness_decaps(
    ffi: cffi.FFI,
    lib,
    func: str,
    paramset: Paramset,
    compliance: bool,
    resilience: bool,
) -> ResultsDict:
    logger.info("Testing harness function %s", func)

    ffi.cdef(
        f"""int {func}(uint8_t *ss, size_t ss_size,
                            const uint8_t *sk, size_t sk_size,
                            const uint8_t *ct, size_t ct_size);
    """,
        override=True,
    )

    decaps = getattr(lib, func)

    # Shared secret size is known in advance.
    c_ss = ffi.new(f"uint8_t[{paramset.ss_size}]")

    def _decaps(sk: bytes, ct: bytes) -> bytes:
        c_sk = ffi.new("uint8_t[]", sk)
        c_ct = ffi.new("uint8_t[]", ct)
        rc = decaps(c_ss, paramset.ss_size, c_sk, len(sk), c_ct, len(ct))
        if rc == 1:
            return bytes(c_ss)
        else:
            raise ValueError(f"{func} failed with status {rc}")

    return test_decaps(_decaps, paramset, compliance=compliance, resilience=resilience)


def _test_harness_invariant(
    ffi: cffi.FFI,
    lib,
    encaps: str,
    decaps: str,
    paramset: Paramset,
    compliance: bool,
    resilience: bool,
) -> ResultsDict:
    logger.info("Testing harness functions %s and %s", encaps, decaps)

    ffi.cdef(
        f"""
        int {encaps}(uint8_t *ct, size_t ct_size,
                     uint8_t *ss, size_t ss_size,
                     const uint8_t *pk, size_t pk_size);
        int {decaps}(uint8_t *ss, size_t ss_size,
                     const uint8_t *sk, size_t sk_size,
                     const uint8_t *ct, size_t ct_size);
    """,
        override=True,
    )

    lib_encaps = getattr(lib, encaps)
    lib_decaps = getattr(lib, decaps)

    # Object sizes are known in advance.
    c_ct = ffi.new(f"uint8_t[{paramset.ct_size}]")
    c_ss = ffi.new(f"uint8_t[{paramset.ss_size}]")

    def _encaps(pk: bytes) -> tuple[bytes, bytes]:
        c_pk = ffi.new("uint8_t[]", pk)
        rc = lib_encaps(c_ct, paramset.ct_size, c_ss, paramset.ss_size, c_pk, len(pk))
        if rc == 1:
            return bytes(c_ct), bytes(c_ss)
        else:
            raise ValueError(f"{encaps} failed with status {rc}")

    def _decaps(sk: bytes, ct: bytes) -> bytes:
        c_sk = ffi.new("uint8_t[]", sk)
        c_ct = ct
        rc = lib_decaps(c_ss, paramset.ss_size, c_sk, len(sk), c_ct, len(ct))
        if rc == 1:
            return bytes(c_ss)
        else:
            raise ValueError(f"{decaps} failed with status {rc}")

    return test_invariant(_encaps, _decaps, paramset)


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
            A list of CC_HQC functions to test.
        compliance:
            Whether to use compliance test vectors.
        resilience:
            Whether to use resilience test vectors.
    """
    logger.info("Found harness functions %s", ", ".join(functions))

    rd = ResultsDict()

    for func in functions:
        match func.split("_"):
            case ["CC", "HQC", _, "encaps"]:
                logger.debug("Found function %s, currently ignored", func)
                continue
            case ["CC", "HQC", _pset, "decaps"]:
                logger.info("Found CC_HQC function %s", func)
                try:
                    paramset = Paramset(f"HQC-{_pset}")
                except ValueError:
                    logger.error(
                        "Invalid parameter set %s for HQC, function skipped", _pset
                    )
                    continue
                rd |= _test_harness_decaps(
                    ffi, lib, func, paramset, compliance, resilience
                )
            case ["CC", "HQC", _pset, "invariant"]:
                try:
                    paramset = Paramset(f"HQC-{_pset}")
                except ValueError:
                    logger.error(
                        "Invalid parameter set %s for HQC, function skipped", _pset
                    )
                    continue
                encaps_name = f"CC_HQC_{_pset}_encaps"
                decaps_name = f"CC_HQC_{_pset}_decaps"
                if encaps_name not in functions:
                    logger.error(
                        "Did not find %s to test invariant, test skipped", encaps_name
                    )
                    continue
                if decaps_name not in functions:
                    logger.error(
                        "Did not find %s to test invariant, test skipped", decaps_name
                    )
                    continue
                rd |= _test_harness_invariant(
                    ffi, lib, encaps_name, decaps_name, paramset, compliance, resilience
                )
            case _:
                logger.warning("Ignored invalid CC_HQC function %s", func)

    return rd
