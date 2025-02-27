"""Module to test HMAC implementations.

The :mod:`crypto_condor.primitives.HMAC` module provides the :func:`test_hmac` function
to test *classes* that implement HMAC. There are two types of interfaces that can be
tested, described by the :protocol:`HMAC` and :protocol:`HMAC_IUF` protocols below.
Supported hash functions are defined by the :enum:`Hash` enum.

This module also exposes internal test functions, mostly to illustrate where the
individual test results come from. We recommend using :func:`test_hmac` and its options
to select which the modes to test and test vectors to use.
"""

import importlib
import json
import logging
import sys
from pathlib import Path
from typing import Any, Protocol, cast

import attrs
import strenum
from rich.progress import track

from crypto_condor.primitives.common import (
    Results,
    ResultsDict,
    TestInfo,
    TestType,
)
from crypto_condor.vectors._hmac.hmac_pb2 import HmacTest, HmacVectors
from crypto_condor.vectors.hmac import Hash

# --------------------------- Module --------------------------------------------------
logger = logging.getLogger(__name__)


def __dir__():  # pragma: no cover
    return [
        # Enums
        Wrapper.__name__,
        # Protocols
        HMAC.__name__,
        HMAC_IUF.__name__,
        # Tests
        test_hmac.__name__,
        test_digest_nist.__name__,
        test_digest_wycheproof.__name__,
        test_verify_nist.__name__,
        test_verify_wycheproof.__name__,
        # Other
        is_hmac_iuf.__name__,
        # Imported
        Hash.__name__,
    ]


# --------------------------- Enums ---------------------------------------------------


class Wrapper(strenum.StrEnum):
    """Supported languages for wrappers."""

    PYTHON = "Python"


# --------------------------- Protocols -----------------------------------------------


class HMAC(Protocol):
    """Class that implements HMAC methods.

    This class represents a simpler interface, where everything is processed in a single
    function. For the common init/update/final interface, see :protocol:`HMAC_IUF`.

    Raising ``NotImplementedError`` is allowed for methods you do not want to test but
    all methods should be present.
    """

    def digest(self, key: bytes, message: bytes) -> bytes:
        """Computes the MAC of a message.

        Args:
            key: The secret HMAC key.
            message: The entire message to authenticate.

        Returns:
            The MAC tag.
        """
        ...

    def verify(self, key: bytes, message: bytes, mac: bytes) -> bool:
        """Verifies a MAC tag.

        Args:
            key: The secret HMAC key.
            message: The entire message to authenticate.
            mac: The MAC tag to verify.

        Returns:
            True if the MAC tag is valid.
        """
        ...


class HMAC_IUF(Protocol):
    """Class that implements HMAC methods.

    This class represents the commonly used init/update/final interface. This interface
    has two final methods, :meth:`final_digest` and :meth:`final_verify`, both of which
    require :meth:`init` and :meth:`update`. For a simpler interface, where only one
    function is required, see :protocol:`HMAC`.

    Raising ``NotImplementedError`` is allowed for (final) methods you do not want to
    test but all methods should be present.
    """

    @classmethod
    def init(cls, key: bytes):
        """Initializes an instance with a key.

        Args:
            key: The secret HMAC key.

        Returns:
            An instance of the class that has been initialized with the given key.
        """
        ...

    def update(self, message: bytes):
        """Processes a new chunk.

        Args:
            message: The next part of the message to process.
        """
        ...

    def final_digest(self) -> bytes:
        """Finalizes the processing.

        Returns:
            The MAC tag.
        """
        ...

    def final_verify(self, mac: bytes) -> bool:
        """Finalizes the processing.

        Returns:
            True if the MAC is valid for the given key and message.
        """
        ...


# --------------------------- Dataclasses----------------------------------------------
@attrs.define
class HmacDigestData:
    """Debug data for HMAC tests."""

    key: bytes
    msg: bytes
    mac: bytes
    res: bytes | None = None

    def __str__(self):
        """Returns a string representation of the fields in use."""
        return f"""key = {self.key.hex()}
msg = {self.msg.hex()}
mac = {self.mac.hex()}
returned mac = {self.res.hex() if self.res else "<none>"}
"""


@attrs.define
class HmacVerifyData:
    """Debug data for HMAC verify tests."""

    key: bytes
    msg: bytes
    mac: bytes

    def __str__(self):
        """Returns a string representation of the fields in use."""
        return f"""key = {self.key.hex()}
msg = {self.msg.hex()}
mac = {self.mac.hex()}
"""


# --------------------------- Internals -----------------------------------------------


def _load_vectors(algo: Hash) -> list[HmacVectors]:
    """Loads HMAC vectors.

    Args:
        algo:
            The hash algorithm to get vectors of.

    Returns:
        A list of vectors.
    """
    vectors_dir = importlib.resources.files("crypto_condor") / "vectors/_hmac"
    vectors = list()

    sources_file = vectors_dir / "hmac.json"
    with sources_file.open("r") as file:
        sources = json.load(file)

    for filename in sources.get(algo, {}):
        vectors_file = vectors_dir / "pb2" / filename
        _vec = HmacVectors()
        logger.debug("Loading HMAC vectors from %s", str(filename))
        try:
            _vec.ParseFromString(vectors_file.read_bytes())
        except Exception:
            logger.exception("Failed to load HMAC vectors from %s", str(filename))
            continue
        vectors.append(_vec)

    return vectors


# --------------------------- Test functions ------------------------------------------
def is_hmac_iuf(hmac: Any) -> bool | None:
    """Checks if a class conforms to the :protocol:`HMAC_IUF` interface.

    Args:
        hmac: The class to check.

    Returns:
        True if the class conforms to the :protocol:`HMAC_IUF` interface, False is it
        conforms to the :protocol:`HMAC` interface, and None if it doesn't conform to
        neither.
    """
    init = hasattr(hmac, "init")
    update = hasattr(hmac, "update")
    if init and update:
        if hasattr(hmac, "final_digest") or hasattr(hmac, "final_verify"):
            logger.debug("Detected HMAC_IUF interface")
            return True
        else:
            logger.error("Found init and update methods, but no final method")
            return None
    elif init:
        logger.error("Found init method but no update method")
        return None
    elif update:
        logger.error("Found update method but no init method")
        return None
    else:
        if hasattr(hmac, "digest") or hasattr(hmac, "verify"):
            logger.debug("Detected HMAC interface")
            return False
        else:
            logger.error("Found no methods")
            return None


def test_digest_nist(hmac: HMAC | HMAC_IUF, hash_function: Hash) -> ResultsDict:
    """Tests an implementation of HMAC digest with NIST test vectors.

    Args:
        hmac:
            The implementation to test. Must conform to either the :protocol:`HMAC`
            interface or the :protocol:`HMAC_IUF` interface.
        hash_function:
            The hash function to use with HMAC.

    Returns:
        A dictionary of results. Can be empty if there are no NIST test vectors for the
        hash function selected.

    Notes:
        Some NIST vectors have truncated MACs. The tag returned by the implementation is
        compared up to the length of the test tag.

    .. versionchanged:: TODO(version)
        Returns :class:`ResultsDict` instead of :class:`Results`.
    """
    all_vectors = _load_vectors(hash_function)
    rd = ResultsDict()

    if not any(vectors.source == "NIST CAVP" for vectors in all_vectors):
        logger.warning("There are no NIST vectors for HMAC-%s", str(hash_function))
        return rd

    IUF_mode = is_hmac_iuf(hmac)
    if IUF_mode is None:
        logger.error("Could not determine interface, test skipped")
        return rd
    elif IUF_mode:
        hmac_iuf = cast(HMAC_IUF, hmac)
    else:
        hmac_s = cast(HMAC, hmac)

    test: HmacTest

    for vectors in all_vectors:
        if vectors.source != "NIST CAVP":
            continue
        res = Results.new("Test HMAC digest with NIST vectors", ["hash_function"])
        rd.add(res, extra_values=[vectors.source])
        for test in track(
            vectors.tests,
            rf"\[HMAC-{str(hash_function)}] Test digest with NIST vectors",
        ):
            info = TestInfo.new_from_test(test, vectors.compliance)
            data = HmacDigestData(test.key, test.msg, test.mac)
            try:
                if IUF_mode:
                    h = hmac_iuf.init(test.key)
                    h.update(test.msg)
                    ret_mac = h.final_digest()
                else:
                    ret_mac = hmac_s.digest(test.key, test.msg)
            except Exception as error:
                logger.debug("Exception caught while testing digest", exc_info=True)
                # NIST vectors do not have invalid tests.
                info.fail(f"Exception caught: {str(error)}", data)
                res.add(info)
                continue
            data.res = ret_mac
            if ret_mac[: len(test.mac)] == test.mac:
                info.ok(data)
            else:
                info.fail("Wrong MAC", data)
            res.add(info)

    return rd


def test_digest_wycheproof(hmac: HMAC | HMAC_IUF, hash_function: Hash) -> ResultsDict:
    """Tests an implementation of HMAC digest with Wycheproof test vectors.

    Args:
        hmac:
            The implementation to test. Must conform to either the :protocol:`HMAC`
            interface or the :protocol:`HMAC_IUF` interface.
        hash_function:
            The hash function to use with HMAC.

    Returns:
        A dictionary of results. Can be empty if there are no Wycheproof test vectors
        for the hash function selected.

    Notes:
        Some Wycheproof vectors have truncated MACs. The tag returned by the
        implementation is compared up to the length of the test tag.

    .. versionchanged:: TODO(version)
        Returns :class:`ResultsDict` instead of :class:`Results`.
    """
    all_vectors = _load_vectors(hash_function)
    rd = ResultsDict()

    if not any(vectors.source == "Wycheproof" for vectors in all_vectors):
        logger.warning(
            "There are no Wycheproof vectors for HMAC-%s", str(hash_function)
        )
        return rd

    IUF_mode = is_hmac_iuf(hmac)
    if IUF_mode is None:
        logger.error("Could not determine interface, test skipped")
        return rd
    elif IUF_mode:
        hmac_iuf = cast(HMAC_IUF, hmac)
    else:
        hmac_s = cast(HMAC, hmac)

    test: HmacTest

    for vectors in all_vectors:
        if vectors.source != "Wycheproof":
            continue
        res = Results.new("Test HMAC digest with Wycheproof vectors", ["hash_function"])
        rd.add(res, extra_values=[vectors.source])
        for test in track(
            vectors.tests,
            rf"\[HMAC-{str(hash_function)}] Test digest with Wycheproof vectors",
        ):
            info = TestInfo.new_from_test(test, vectors.compliance)
            data = HmacDigestData(test.key, test.msg, test.mac)
            try:
                if IUF_mode:
                    h = hmac_iuf.init(test.key)
                    h.update(test.msg)
                    ret_mac = h.final_digest()
                else:
                    ret_mac = hmac_s.digest(test.key, test.msg)
            except Exception as error:
                logger.debug("Exception caught while testing digest", exc_info=True)
                # Implementations should catch the errors.
                info.fail(f"Exception caught: {str(error)}", data)
                res.add(info)
                continue
            data.res = ret_mac
            is_same_mac = ret_mac[: len(test.mac)] == test.mac
            match (test.type, is_same_mac):
                case (TestType.VALID, True):
                    info.ok(data)
                case (TestType.VALID, False):
                    info.fail("Wrong MAC", data)
                case (TestType.INVALID, True):
                    info.fail("Returned MAC matches invalid MAC", data)
                case (TestType.INVALID, False):
                    info.ok(data)
                case _:
                    raise ValueError(
                        f"Invalid test result ({test.type}, {is_same_mac})"
                    )
            res.add(info)

    return rd


def test_verify_nist(hmac: HMAC | HMAC_IUF, hash_function: Hash) -> ResultsDict:
    """Tests an implementation of HMAC verify with NIST vectors.

    Args:
        hmac:
            The implementation to test. Must conform to either the :protocol:`HMAC`
            interface or the :protocol:`HMAC_IUF` interface.
        hash_function:
            The hash function to use with HMAC.

    Returns:
        A dictionary of results. Can be empty if there are no NIST test vectors for the
        hash function selected.

    Notes:
        Some NIST vectors have truncated MACs. The tag returned by the implementation is
        compared up to the length of the test tag.

    .. versionchanged:: TODO(version)
        Returns :class:`ResultsDict` instead of :class:`Results`.
    """
    all_vectors = _load_vectors(hash_function)
    rd = ResultsDict()

    if not any(vectors.source == "NIST CAVP" for vectors in all_vectors):
        logger.warning("There are no NIST vectors for HMAC-%s", str(hash_function))
        return rd

    is_iuf = is_hmac_iuf(hmac)
    if is_iuf is None:
        logger.error("Could not determine interface, test skipped")
        return rd
    elif is_iuf:
        IUF_mode = True
        hmac_iuf = cast(HMAC_IUF, hmac)
    else:
        IUF_mode = False
        hmac_s = cast(HMAC, hmac)

    test: HmacTest
    for vectors in all_vectors:
        if vectors.source != "NIST CAVP":
            continue
        res = Results.new("Test HMAC verify with NIST vectors", ["hash_function"])
        rd.add(res, extra_values=[vectors.source])
        for test in track(
            vectors.tests,
            rf"\[HMAC-{str(hash_function)}] Test verify with NIST vectors",
        ):
            info = TestInfo.new_from_test(test, vectors.compliance)
            data = HmacVerifyData(test.key, test.msg, test.mac)
            try:
                if IUF_mode:
                    h = hmac_iuf.init(test.key)
                    h.update(test.msg)
                    is_valid = h.final_verify(test.mac)
                else:
                    is_valid = hmac_s.verify(test.key, test.msg, test.mac)
            except Exception as error:
                logger.debug("Exception caught while testing verify", exc_info=True)
                # Errors should be caught by the implementation.
                info.fail(f"Exception caught: {str(error)}", data)
                res.add(info)
                continue
            # No invalid NIST vectors.
            if is_valid:
                info.ok(data)
            else:
                info.fail("Valid MAC rejected", data)
            res.add(info)
    return rd


def test_verify_wycheproof(hmac: HMAC | HMAC_IUF, hash_function: Hash) -> ResultsDict:
    """Tests an implementation of HMAC verify with Wycheproof test vectors.

    Args:
        hmac:
            The implementation to test. Must conform to either the :protocol:`HMAC`
            interface or the :protocol:`HMAC_IUF` interface.
        hash_function:
            The hash function to use with HMAC.

    Returns:
        A dictionary of results. Can be empty if there are no Wycheproof test vectors
        for the hash function selected.

    Notes:
        Some Wycheproof vectors have truncated MACs. The tag returned by the
        implementation is compared up to the length of the test tag.

    .. versionchanged:: TODO(version)
        Returns :class:`ResultsDict` instead of :class:`Results`.
    """
    all_vectors = _load_vectors(hash_function)
    rd = ResultsDict()

    if not any(vectors.source == "Wycheproof" for vectors in all_vectors):
        logger.warning(
            "There are no Wycheproof vectors for HMAC-%s", str(hash_function)
        )
        return rd

    IUF_mode = is_hmac_iuf(hmac)
    if IUF_mode is None:
        logger.error("Could not determine interface, test skipped")
        return rd
    elif IUF_mode:
        hmac_iuf = cast(HMAC_IUF, hmac)
    else:
        hmac_s = cast(HMAC, hmac)

    test: HmacTest

    for vectors in all_vectors:
        if vectors.source != "Wycheproof":
            continue
        res = Results.new("Test HMAC verify with Wycheproof vectors", ["hash_function"])
        rd.add(res, extra_values=[vectors.source])
        for test in track(
            vectors.tests,
            rf"\[HMAC-{str(hash_function)}] Test verify with Wycheproof vectors",
        ):
            info = TestInfo.new_from_test(test, vectors.compliance)
            data = HmacVerifyData(test.key, test.msg, test.mac)
            try:
                if IUF_mode:
                    h = hmac_iuf.init(test.key)
                    h.update(test.msg)
                    is_valid = h.final_verify()
                else:
                    is_valid = hmac_s.verify(test.key, test.msg, test.mac)
            except Exception as error:
                logger.debug("Exception caught while testing verify", exc_info=True)
                # Implementations should catch the errors.
                info.fail(f"Exception caught: {str(error)}", data)
                res.add(info)
                continue
            match (test.type, is_valid):
                case (TestType.VALID, True) | (TestType.INVALID, False):
                    info.ok(data)
                case (TestType.VALID, False):
                    info.fail("Valid MAC rejected", data)
                case (TestType.INVALID, True):
                    info.fail("Invalid MAC accepted", data)
                case _:
                    raise ValueError(f"Invalid result ({test.type}, {is_valid})")
            res.add(info)

    return rd


def test_hmac(
    hmac: HMAC | HMAC_IUF,
    hash_function: Hash,
    *,
    compliance: bool = True,
    resilience: bool = False,
    skip_digest: bool = False,
    skip_verify: bool = False,
) -> ResultsDict:
    """Tests an implementation of HMAC using test vectors.

    Test vectors are selected with the ``compliance`` and ``resilience`` options. SHA-3
    functions are not covered by NIST vectors (see :class:`HmacVectors`).

    Args:
        hmac:
            The implementation to test. Must conform to either the :protocol:`HMAC`
            interface or the :protocol:`HMAC_IUF` interface.
        hash_function:
            The hash function to use with this HMAC implementation.

    Keyword Args:
        compliance:
            Whether to use compliance test vectors.
        resilience:
            Whether to use resilience test vectors.
        skip_digest:
            If True, skip testing the digest function.
        skip_verify:
            If True, skip testing the verify function.
    """
    rd = ResultsDict()

    if not compliance and not resilience:
        logger.warning("No test vectors selected (compliance and resilience are False)")
        return rd
    if skip_digest and skip_verify:
        logger.warning("No methods to test (skip_digest and skip_verify are True)")
        return rd

    # Log not compliance and not resilience so the user can see when some test vectors
    # are not used.
    if not compliance:
        logger.debug("compliance is False, not using NIST vectors")
    if not resilience:
        logger.debug("resilience is False, not using Wycheproof vectors")

    if not skip_digest:
        if compliance:
            rd |= test_digest_nist(hmac, hash_function)
        if resilience:
            rd |= test_digest_wycheproof(hmac, hash_function)
    if not skip_verify:
        if compliance:
            rd |= test_verify_nist(hmac, hash_function)
        if resilience:
            rd |= test_verify_wycheproof(hmac, hash_function)

    return rd


# --------------------------- Runners -------------------------------------------------
def _run_python_wrapper(
    hash_function: Hash,
    compliance: bool,
    resilience: bool,
    skip_digest: bool,
    skip_verify: bool,
) -> ResultsDict:
    file = Path().cwd() / "HMAC_wrapper.py"
    if not file.exists():
        raise FileNotFoundError("Can't find HMAC_wrapper.py in the current directory")
    logger.info("Running HMAC Python wrapper")
    sys.path.insert(0, str(Path.cwd()))
    imported = "HMAC_wrapper" in sys.modules.keys()
    try:
        wrapper = importlib.import_module("HMAC_wrapper")
    except ModuleNotFoundError as error:
        logger.error("Could not load wrapper: %s", str(error))
        raise
    if imported:
        logger.debug("Reloading HMAC Python wrapper")
        wrapper = importlib.reload(wrapper)
    if not hasattr(wrapper, "CC_HMAC"):
        logger.warning("Class CC_HMAC not found, cannot test wrapper")
        return ResultsDict()
    hmac = wrapper.CC_HMAC
    rd = test_hmac(
        hmac(),
        hash_function,
        compliance=compliance,
        resilience=resilience,
        skip_digest=skip_digest,
        skip_verify=skip_verify,
    )
    return rd


def run_wrapper(
    language: Wrapper,
    hash_function: Hash,
    compliance: bool,
    resilience: bool,
    skip_digest: bool,
    skip_verify: bool,
) -> ResultsDict:
    """Runs a wrapper."""
    match language:
        case Wrapper.PYTHON:
            return _run_python_wrapper(
                hash_function, compliance, resilience, skip_digest, skip_verify
            )
