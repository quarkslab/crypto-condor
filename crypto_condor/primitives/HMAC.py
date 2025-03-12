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
import inspect
import json
import logging
import sys
from pathlib import Path
from typing import Any, Protocol, cast

import attrs
import cffi
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


class Digest(Protocol):
    """Represents the HMAC digest operation.

    .. versionadded:: TODO(version)
        Replaces :meth:`HMAC.digest`.
    """

    def __call__(self, key: bytes, msg: bytes) -> bytes:
        """Generates a MAC using HMAC.

        Args:
            key:
                The secret key.
            msg:
                The message to authenticate.

        Returns:
            The MAC, in bytes.
        """
        ...


class Verify(Protocol):
    """Represents the verification of an HMAC tag.

    Some implementations may offer a ``verify`` method, while others expect the user to
    generate a tag from the key and message, and compare it with the existing tag.

    .. versionadded:: TODO(version)
        Replaces :meth:`HMAC.verify`.
    """

    def __call__(self, key: bytes, msg: bytes, mac: bytes, mac_len: int) -> bool:
        """Verifies a HMAC tag.

        The size of the MAC is given to indicate that the tag may be truncated,
        therefore shorter than the digest size.

        Args:
            key:
                The secret key.
            msg:
                The message to authenticate.
            mac:
                The tag to verify.
            mac_len:
                The size of the MAC in bytes. Equal to len(mac).

        Returns:
            True if the tags match, False otherwise.
        """
        ...


class HMAC(Protocol):
    """Class that implements HMAC methods.

    This class represents a simpler interface, where everything is processed in a single
    function. For the common init/update/final interface, see :protocol:`HMAC_IUF`.

    Raising ``NotImplementedError`` is allowed for methods you do not want to test but
    all methods should be present.

    .. deprecated:: TODO(version)
        Use :protocol:`Digest` and :protocol:`Verify` instead.
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

    .. deprecated:: TODO(version)
        Use :protocol:`Digest` and :protocol:`Verify` instead.
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


def test_digest(
    digest: Digest,
    hash_function: Hash,
    *,
    compliance: bool = True,
    resilience: bool = False,
) -> ResultsDict:
    """Tests an implementation of the HMAC digest operation.

    The implementation is called to generate a tag for a given key and message. The
    returned tag is compared to the test value. Some test values are *truncated*: in
    that case, the comparison is performed up to the length of the truncated tag.

    Args:
        digest:
            The implementation to test.
        hash_function:
            The hash function used by the implementation.

    Keyword Args:
        compliance:
            Whether to use compliance test vectors.
        resilience:
            Whether to use resilience test vectors.

    Returns:
        A dictionary of results.

    Example:
        Let's test the built-in HMAC implementation.

        >>> import hmac

        We also import the HMAC module from |cc|.

        >>> from crypto_condor.primitives import HMAC

        We create our function conforming to :protocol:`Digest` using SHA-256.

        >>> def digest_sha256(key: bytes, msg: bytes) -> bytes:
        ...     return hmac.digest(key, msg, "sha256")

        Then we test it.

        >>> rd = HMAC.test_digest(digest_sha256, HMAC.Hash.SHA_256)
        [HMAC-SHA-256] Test digest ...
        >>> assert rd.check()

    .. versionadded:: TODO(version)
        Replaces testing ``digest`` with :func:`test_hmac`.
    """
    all_vectors = _load_vectors(hash_function)
    rd = ResultsDict()

    test: HmacTest

    for vectors in all_vectors:
        if not compliance and vectors.compliance:
            continue
        if not resilience and not vectors.compliance:
            continue

        res = Results.new("Test HMAC digest", ["hash_function"])
        rd.add(res, extra_values=[vectors.source])

        for test in track(vectors.tests, rf"\[HMAC-{str(hash_function)}] Test digest"):
            info = TestInfo.new_from_test(test, vectors.compliance)
            data = HmacDigestData(test.key, test.msg, test.mac)
            try:
                ret_mac = digest(test.key, test.msg)
            except NotImplementedError:
                logger.warning(
                    "HMAC-%s digest not implemented, test skipped", str(hash_function)
                )
                return rd
            except Exception as error:
                # Currently no invalid test should fail when calling digest.
                info.fail(f"Exception caught: {str(error)}", data)
                logger.debug("Exception caught when running HMAC.digest", exc_info=True)
                res.add(info)
                continue
            data.res = ret_mac
            # Some test vectors have truncated MACs.
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
                    # There are no acceptable test for now.
                    raise ValueError(f"Invalid result ({test.type}, {is_same_mac})")
            res.add(info)

    return rd


def test_verify(
    verify: Verify,
    hash_function: Hash,
    *,
    compliance: bool = True,
    resilience: bool = False,
) -> ResultsDict:
    """Tests an implementation of HMAC tag verification.

    Args:
        verify:
            The implementation to test.
        hash_function:
            The hash function used by the implementation.

    Keyword Args:
        compliance:
            Whether to use compliance test vectors.
        resilience:
            Whether to use resilience test vectors.

    Returns:
        A dictionary of results.

    Example:
        Let's test the built-in HMAC implementation.

        >>> import hmac

        We also import the HMAC module from |cc|.

        >>> from crypto_condor.primitives import HMAC

        We create our function conforming to :protocol:`Verify` using SHA-256.

        >>> def verify_sha256(key: bytes, msg: bytes, mac: bytes, mac_len: int) -> bool:
        ...     ref_mac = hmac.digest(key, msg, "sha256")
        ...     return hmac.compare_digest(ref_mac[: mac_len], mac)

        Then we test it.

        >>> rd = HMAC.test_verify(verify_sha256, HMAC.Hash.SHA_256)
        [HMAC-SHA-256] Test verify ...
        >>> assert rd.check()

    .. versionadded:: TODO(version)
        Replaces testing ``verify`` with :func:`test_hmac`.
    """
    all_vectors = _load_vectors(hash_function)
    rd = ResultsDict()

    test: HmacTest

    for vectors in all_vectors:
        if not compliance and vectors.compliance:
            continue
        if not resilience and not vectors.compliance:
            continue

        res = Results.new("Test HMAC verify", ["hash_function"])
        rd.add(res, extra_values=[vectors.source])

        for test in track(vectors.tests, rf"\[HMAC-{str(hash_function)}] Test verify"):
            info = TestInfo.new_from_test(test, vectors.compliance)
            data = HmacVerifyData(test.key, test.msg, test.mac)
            try:
                ret_valid = verify(test.key, test.msg, test.mac, len(test.mac))
            except NotImplementedError:
                logger.warning(
                    "HMAC-%s verify not implemented, test skipped", str(hash_function)
                )
                return rd
            except Exception as error:
                logger.debug("Exception caught when running HMAC.verify", exc_info=True)
                # Errors should be caught by the implementation.
                info.fail(f"Exception caught: {str(error)}", data)
                res.add(info)
                continue
            match (test.type, ret_valid):
                case (TestType.VALID, True) | (TestType.INVALID, False):
                    info.ok(data)
                case (TestType.VALID, False):
                    info.fail("Valid MAC rejected", data)
                case (TestType.INVALID, True):
                    info.fail("Invalid MAC accepted", data)
                case _:
                    # There are no acceptable test for now.
                    raise ValueError(f"Invalid result ({test.type}, {ret_valid})")
            res.add(info)

    return rd


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
            except NotImplementedError:
                return rd
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
            except NotImplementedError:
                return rd
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
            except NotImplementedError:
                return rd
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
            except NotImplementedError:
                return rd
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

    .. deprecated:: TODO(version)
        Use :func:`test_digest` and :func:`test_verify` instead.
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


def test_wrapper_python(
    wrapper: Path, compliance: bool, resilience: bool
) -> ResultsDict:
    """Tests a HMAC Python wrapper.

    Args:
        wrapper:
            The path to the wrapper.
        compliance:
            Whether to use compliance test vectors.
        resilience:
            Whether to use resilience test vectors.
    """
    logger.info("Running Python HMAC wrapper: '%s'", str(wrapper.name))
    sys.path.insert(0, str(wrapper.parent.absolute()))
    already_imported = wrapper.stem in sys.modules.keys()
    try:
        hmac_wrapper = importlib.import_module(wrapper.stem)
    except ModuleNotFoundError as error:
        logger.error("Can't import wrapper: '%s'", str(error))
        raise
    if already_imported:
        logger.debug("Reloading HMAC wrapper: '%s'", wrapper.stem)
        hmac_wrapper = importlib.reload(hmac_wrapper)

    rd = ResultsDict()

    for func, _ in inspect.getmembers(hmac_wrapper, inspect.isfunction):
        match func.split("_"):
            case ["CC", "HMAC", "digest", *parts]:
                logger.info("Found CC_HMAC function %s", func)
                try:
                    algo = Hash.from_funcname(parts)
                except ValueError:
                    logger.error(
                        "Invalid algorithm %s for HMAC, skipped", "_".join(parts)
                    )
                    continue
                rd |= test_digest(
                    getattr(hmac_wrapper, func),
                    algo,
                    compliance=compliance,
                    resilience=resilience,
                )
            case ["CC", "HMAC", "verify", *parts]:
                logger.info("Found CC_HMAC function %s", func)
                try:
                    algo = Hash.from_funcname(parts)
                except ValueError:
                    logger.error(
                        "Invalid algorithm %s for HMAC, skipped", "_".join(parts)
                    )
                    continue
                rd |= test_verify(
                    getattr(hmac_wrapper, func),
                    algo,
                    compliance=compliance,
                    resilience=resilience,
                )
            case ["CC", "HMAC", *_]:
                logger.warning("Ignored unknown CC_HMAC function %s", func)
                continue
            case _:
                pass

    return rd


def test_wrapper(wrapper: Path, compliance: bool, resilience: bool) -> ResultsDict:
    """Tests an HMAC wrapper.

    Calls the corresponding runner depending on the file extension.

    Args:
        wrapper:
            The path to the wrapper.
        compliance:
            Whether to use compliance test vectors.
        resilience:
            Whether to use resilience test vectors.
    """
    if not wrapper.is_file():
        raise FileNotFoundError(f"No wrapper named {str(wrapper)} found")
    match wrapper.suffix:
        case ".py":
            return test_wrapper_python(wrapper, compliance, resilience)
        case _:
            raise ValueError(f"No runner defined for {wrapper.suffix} wrappers")


# --------------------------- Harness -------------------------------------------------


def _test_harness_digest(ffi: cffi.FFI, lib, function: str, algo: Hash) -> ResultsDict:
    """Tests a harness for digest."""
    logger.info("Testing harness function %s", function)

    ffi.cdef(
        f"""int {function}(
                uint8_t *mac, const size_t mac_size,
                const uint8_t *key, const size_t key_size,
                const uint8_t *msg, const size_t msg_size);
        """
    )
    digest = getattr(lib, function)

    mac_len = algo.digest_size // 8
    c_mac = ffi.new(f"uint8_t[{mac_len}]")

    def _digest(key: bytes, msg: bytes) -> bytes:
        c_key = ffi.new("uint8_t[]", key)
        c_msg = ffi.new("uint8_t[]", msg)
        rc = digest(c_mac, mac_len, c_key, len(key), c_msg, len(msg))
        if rc != 1:
            raise ValueError(f"{function} failed with code {rc}")
        return bytes(c_mac)

    return test_digest(_digest, algo)


def _test_harness_verify(ffi: cffi.FFI, lib, function: str, algo: Hash) -> ResultsDict:
    """Tests a harness for verify."""
    logger.info("Testing harness function %s", function)

    ffi.cdef(
        f"""int {function}(
                const uint8_t *mac, const size_t mac_size,
                const size_t md_size,
                const uint8_t *key, const size_t key_size,
                const uint8_t *msg, const size_t msg_size);
        """
    )
    verify = getattr(lib, function)
    c_md_size = algo.digest_size // 8

    def _verify(key: bytes, msg: bytes, mac: bytes, mac_len: int) -> bool:
        c_key = ffi.new("uint8_t[]", key)
        c_msg = ffi.new("uint8_t[]", msg)
        c_mac = ffi.new("uint8_t[]", mac)
        rc = verify(c_mac, mac_len, c_md_size, c_key, len(key), c_msg, len(msg))
        if rc == 1:
            return True
        elif rc == 0:
            return False
        else:
            raise ValueError(f"{function} failed with code {rc}")

    return test_verify(_verify, algo)


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
            A list of functions to test.
        compliance:
            Whether to use compliance test vectors.
        resilience:
            Whether to use resilience test vectors.
    """
    logger.info("Found harness functions %s", ", ".join(functions))

    rd = ResultsDict()

    for func in functions:
        match func.split("_"):
            case ["CC", "HMAC", "digest", *parts]:
                try:
                    algo = Hash.from_funcname(parts)
                except ValueError as error:
                    logger.error(str(error))
                    continue
                rd |= _test_harness_digest(ffi, lib, func, algo)
            case ["CC", "HMAC", "verify", *parts]:
                try:
                    algo = Hash.from_funcname(parts)
                except ValueError as error:
                    logger.error(str(error))
                    continue
                rd |= _test_harness_verify(ffi, lib, func, algo)
            case _:
                logger.debug("Skipped invalid CC_HMAC function %s", func)
                continue

    return rd
