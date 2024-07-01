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
import logging
import sys
from pathlib import Path
from typing import Any, Protocol, cast

import attrs
import strenum
from rich.progress import track

from crypto_condor.primitives.common import DebugInfo, Results, ResultsDict, TestType
from crypto_condor.vectors.HMAC import Hash, HmacVectors

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

    info: DebugInfo
    key: bytes
    msg: bytes
    mac: bytes
    res: bytes | None = None

    def __str__(self):
        """Returns a string representation of the fields in use."""
        s = f"""{str(self.info)}
key = {self.key.hex()}
msg = {self.msg.hex()}
mac = {self.mac.hex()}
res = {self.res.hex() if self.res else '<none>'}
"""
        return s


@attrs.define
class HmacVerifyData:
    """Debug data for HMAC verify tests."""

    info: DebugInfo
    key: bytes
    msg: bytes
    mac: bytes
    res: bool | None

    def __str__(self):
        """Returns a string representation of the fields in use."""
        s = f"""{str(self.info)}
key = {self.key.hex()}
msg = {self.msg.hex()}
mac = {self.mac.hex()}
res = {self.res}
"""
        return s


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


def test_digest_nist(hmac: HMAC | HMAC_IUF, hash_function: Hash) -> Results | None:
    """Tests an implementation of HMAC digest with NIST test vectors.

    Args:
        hmac: The implementation to test. Must conform to either the :protocol:`HMAC`
            interface or the :protocol:`HMAC_IUF` interface.
        hash_function: The hash function to use with HMAC.

    Returns:
        The results of testing the implementation, or None if there are no NIST vectors
        for the given hash function.

    Notes:
        Some NIST vectors have truncated MACs. To use them, we truncate the output of
        the implementation to compare them.
    """
    vectors = HmacVectors.load(hash_function)
    if vectors.nist is None:
        logger.warning(
            "Compliance vectors selected but there are no NIST vectors for HMAC-%s",
            str(hash_function),
        )
        return None

    results = Results(
        "HMAC",
        test_digest_nist.__name__,
        "Tests an implementation of HMAC.digest with NIST test vectors",
        {"hash_function": hash_function},
    )
    logger.debug(
        "Using NIST vectors %s for HMAC-%s", vectors.nist.filename, str(hash_function)
    )

    IUF_mode = is_hmac_iuf(hmac)
    if IUF_mode is None:
        logger.error("Could not determine interface, test skipped")
        return None
    elif IUF_mode:
        hmac_iuf = cast(HMAC_IUF, hmac)
    else:
        hmac_s = cast(HMAC, hmac)

    for test in track(
        vectors.nist.tests, f"[NIST] Generating MACs with HMAC-{str(hash_function)}"
    ):
        info = DebugInfo(test.count, TestType.VALID, ["Compliance"])
        try:
            if IUF_mode:
                h = hmac_iuf.init(test.key)
                h.update(test.msg)
                mac = h.final_digest()
            else:
                mac = hmac_s.digest(test.key, test.msg)
        except Exception as error:
            info.error_msg = f"Error running HMAC digest: {error}"
            logger.debug("Error running HMAC digest", exc_info=True)
            results.add(HmacDigestData(info, test.key, test.msg, test.mac))
            continue
        # Some test vectors have truncated MACs.
        mac = mac[: test.tlen]
        if mac == test.mac:
            info.result = True
        else:
            info.error_msg = "Wrong MAC returned"
        results.add(HmacDigestData(info, test.key, test.msg, test.mac, mac))
    return results


def test_digest_wycheproof(
    hmac: HMAC | HMAC_IUF, hash_function: Hash
) -> Results | None:
    """Tests an implementation of HMAC digest with Wycheproof test vectors.

    Args:
        hmac: The implementation to test. Must conform to either the :protocol:`HMAC`
            interface or the :protocol:`HMAC_IUF` interface.
        hash_function: The hash function to use with HMAC.

    Returns:
        The results of testing the implementation, or None if there are no Wycheproof
        vectors for the given hash function.

    Notes:
        Some Wycheproof vectors have truncated MACs. To use them, we truncate the output
        of the implementation to compare them.
    """
    vectors = HmacVectors.load(hash_function)
    if vectors.wycheproof is None:
        return None

    results = Results(
        "HMAC",
        test_digest_wycheproof.__name__,
        "Tests an implementation of HMAC.digest with Wycheproof test vectors",
        {"hash_function": hash_function},
        notes=vectors.wycheproof.notes,
    )
    logger.debug(
        "Using Wycheproof vectors %s for HMAC-%s",
        vectors.wycheproof.filename,
        str(hash_function),
    )

    is_iuf = is_hmac_iuf(hmac)
    if is_iuf is None:
        logger.error("Could not determine interface, test skipped")
        return None
    elif is_iuf:
        IUF_mode = True
        hmac_iuf = cast(HMAC_IUF, hmac)
    else:
        IUF_mode = False
        hmac_s = cast(HMAC, hmac)

    for group in track(
        vectors.wycheproof.groups,
        f"[Wycheproof] Generating MACs with HMAC-{str(hash_function)}",
    ):
        for test in group.tests:
            test_type = TestType(test.result)
            info = DebugInfo(test.count, test_type, test.flags)
            try:
                if IUF_mode:
                    h = hmac_iuf.init(test.key)
                    h.update(test.msg)
                    mac = h.final_digest()
                else:
                    mac = hmac_s.digest(test.key, test.msg)
            except Exception as error:
                if test_type == TestType.INVALID:
                    info.result = True
                else:
                    info.error_msg = f"Error running HMAC digest: {error}"
                    logger.debug("Error running HMAC digest", exc_info=True)
                results.add(HmacDigestData(info, test.key, test.msg, test.mac))
                continue
            mac = mac[: len(test.mac)]
            res = mac == test.mac
            match (test_type, res):
                case (TestType.VALID, True) | (TestType.INVALID, False):
                    info.result = True
                case (TestType.VALID, False) | (TestType.INVALID, True):
                    info.error_msg = "Wrong MAC returned"
            results.add(HmacDigestData(info, test.key, test.msg, test.mac, mac))

    return results


def test_verify_nist(hmac: HMAC | HMAC_IUF, hash_function: Hash) -> Results | None:
    """Tests an implementation of HMAC verify with NIST vectors.

    Args:
        hmac: The implementation to test. Must conform to either the :protocol:`HMAC`
            interface or the :protocol:`HMAC_IUF` interface.
        hash_function: The hash function to use with HMAC.

    Returns:
        The results or None if there are no NIST vectors for the given hash function.

    Notes:
        Some NIST vectors have truncated MACs. As implementations usually expect the
        entire tag for verification, we skip these vectors.
    """
    vectors = HmacVectors.load(hash_function)
    if vectors.nist is None:
        logger.warning(
            "Compliance vectors selected but there are no NIST vectors for HMAC-%s",
            str(hash_function),
        )
        return None

    results = Results(
        "HMAC",
        test_verify_nist.__name__,
        "Tests an implementation of HMAC.verify with NIST test vectors",
        {"hash_function": hash_function},
    )
    logger.debug(
        "Using NIST vectors %s for HMAC-%s", vectors.nist.filename, str(hash_function)
    )

    is_iuf = is_hmac_iuf(hmac)
    if is_iuf is None:
        logger.error("Could not determine interface, test skipped")
        return None
    elif is_iuf:
        IUF_mode = True
        hmac_iuf = cast(HMAC_IUF, hmac)
    else:
        IUF_mode = False
        hmac_s = cast(HMAC, hmac)

    for test in track(
        vectors.nist.tests, f"[NIST] Verifying MACs with HMAC-{str(hash_function)}"
    ):
        if test.tlen * 8 != hash_function.digest_size:
            continue
        info = DebugInfo(test.count, TestType.VALID, ["Compliance"])
        try:
            if IUF_mode:
                h = hmac_iuf.init(test.key)
                h.update(test.msg)
                is_valid = h.final_verify(test.mac)
            else:
                is_valid = hmac_s.verify(test.key, test.msg, test.mac)
        except Exception as error:
            info.error_msg = f"Error running HMAC verify: {error}"
            logger.debug("Error running HMAC verify", exc_info=True)
            results.add(HmacVerifyData(info, test.key, test.msg, test.mac, None))
            continue
        if is_valid:
            info.result = True
        else:
            info.error_msg = "Valid MAC considered invalid"
        results.add(HmacVerifyData(info, test.key, test.msg, test.mac, is_valid))
    return results


def test_verify_wycheproof(
    hmac: HMAC | HMAC_IUF, hash_function: Hash
) -> Results | None:
    """Tests an implementation of HMAC verify with Wycheproof test vectors.

    Args:
        hmac: The implementation to test. Must conform to either the :protocol:`HMAC`
            interface or the :protocol:`HMAC_IUF` interface.
        hash_function: The hash function to use with HMAC.

    Returns:
        The results of testing the implementation, or None if there are no Wycheproof
        vectors for the given hash function.

    Notes:
        Some Wycheproof vectors have truncated MACs. As implementations usually expect
        the entire tag for verification, we skip these vectors.
    """
    vectors = HmacVectors.load(hash_function)
    if vectors.wycheproof is None:
        return None

    results = Results(
        "HMAC",
        test_verify_wycheproof.__name__,
        "Tests an implementation of HMAC.verify with Wycheproof test vectors",
        {"hash_function": hash_function},
        notes=vectors.wycheproof.notes,
    )
    logger.debug(
        "Using Wycheproof vectors %s for HMAC-%s",
        vectors.wycheproof.filename,
        str(hash_function),
    )

    is_iuf = is_hmac_iuf(hmac)
    if is_iuf is None:
        logger.error("Could not determine interface, test skipped")
        return None
    elif is_iuf:
        IUF_mode = True
        hmac_iuf = cast(HMAC_IUF, hmac)
    else:
        IUF_mode = False
        hmac_s = cast(HMAC, hmac)

    for group in track(
        vectors.wycheproof.groups,
        f"[Wycheproof] Generating MACs with HMAC-{str(hash_function)}",
    ):
        for test in group.tests:
            if len(test.mac) * 8 != hash_function.digest_size:
                continue
            test_type = TestType(test.result)
            info = DebugInfo(test.count, test_type, test.flags)
            try:
                if IUF_mode:
                    h = hmac_iuf.init(test.key)
                    h.update(test.msg)
                    res = h.final_verify(test.mac)
                else:
                    res = hmac_s.verify(test.key, test.msg, test.mac)
            except Exception as error:
                if test_type == TestType.INVALID:
                    info.result = True
                else:
                    info.error_msg = f"Error running HMAC verify: {error}"
                    logger.debug("Error running HMAC verify", exc_info=True)
                results.add(HmacVerifyData(info, test.key, test.msg, test.mac, None))
                continue
            match (test_type, res):
                case (TestType.VALID, True) | (TestType.INVALID, False):
                    info.result = True
                case (TestType.VALID, False) | (TestType.INVALID, True):
                    info.error_msg = "Wrong MAC returned"
            results.add(HmacVerifyData(info, test.key, test.msg, test.mac, res))

    return results


def test_hmac(
    hmac: HMAC | HMAC_IUF,
    hash_function: Hash,
    *,
    compliance: bool = True,
    resilience: bool = False,
    skip_digest: bool = False,
    skip_verify: bool = False,
):
    """Tests an implementation of HMAC using test vectors.

    Test vectors are selected with the ``compliance`` and ``resilience`` options. SHA-3
    functions are not covered by NIST vectors (see :class:`HmacVectors`).

    Args:
        hmac: The implementation to test. Must conform to either the :protocol:`HMAC`
            interface or the :protocol:`HMAC_IUF` interface.
        hash_function: The hash function to use with this HMAC implementation.

    Keyword Args:
        compliance: Whether to use compliance test vectors.
        resilience: Whether to use resilience test vectors.
        skip_digest: If True, skip testing the digest function.
        skip_verify: If True, skip testing the verify function.

    Examples:
        Let's test PyCryptodome's HMAC-SHA256 implementation.

        >>> from Crypto.Hash import HMAC as pyHMAC
        >>> from Crypto.Hash import SHA256

        To test the implementation we have to create a class that conforms to either of
        the two interfaces. We'll test the simple :protocol:`HMAC` interface first. For
        this, we create two methods: ``digest`` and ``verify``.

        >>> class MyHmac:
        ...     def digest(self, key: bytes, message: bytes) -> bytes:
        ...         h = pyHMAC.new(key, message, digestmod=SHA256)
        ...         return h.digest()
        ...     def verify(self, key: bytes, message: bytes, mac: bytes) -> bool:
        ...         h = pyHMAC.new(key, message, digestmod=SHA256)
        ...         try:
        ...             h.verify(mac)
        ...             return True
        ...         except ValueError:
        ...             return False

        We pass an instance of this class to this function.

        >>> from crypto_condor.primitives import HMAC
        >>> hash_function = HMAC.Hash.SHA_256
        >>> rd = HMAC.test_hmac(MyHmac(), hash_function)
        [NIST] Generating MACs ...
        >>> assert rd.check()

        We can also test the more complex init/update/final interface.

        >>> class MyHmacIuf:
        ...     _obj: pyHMAC.HMAC
        ...     @classmethod
        ...     def init(cls, key: bytes):
        ...         h = cls()
        ...         h._obj = pyHMAC.new(key, digestmod=SHA256)
        ...         return h
        ...     def update(self, data: bytes):
        ...         self._obj.update(data)
        ...     def final_digest(self) -> bytes:
        ...         return self._obj.digest()
        ...     def final_verify(self, mac: bytes) -> bool:
        ...         try:
        ...             self._obj.verify(mac)
        ...             return True
        ...         except ValueError:
        ...             return False

        This time we enable Wycheproof vectors, for illustration purposes.

        >>> rd = HMAC.test_hmac(MyHmacIuf(), hash_function, resilience=True)
        [NIST] Generating MACs ...
        >>> assert rd.check()
    """
    logger.info("Testing an HMAC implementation")

    rd = ResultsDict()

    if not compliance and not resilience:
        logger.warning("No test vectors selected (compliance and resilience are False)")
        return rd
    if skip_digest and skip_verify:
        logger.warning("No methods to test (skip_digest and skip_verify are True)")
        return rd

    # Log not compliance and not resilience so the user can easily see when some test
    # vectors are not used.
    if not compliance:
        logger.debug("compliance is False, not using NIST vectors")
    if not resilience:
        logger.debug("resilience is False, not using Wycheproof vectors")

    if not skip_digest:
        if compliance:
            r = test_digest_nist(hmac, hash_function)
            if r is not None:
                rd["HMAC/digest/nist"] = r
        if resilience:
            r = test_digest_wycheproof(hmac, hash_function)
            if r is not None:
                rd["HMAC/digest/wycheproof"] = r
    if not skip_verify:
        if compliance:
            r = test_verify_nist(hmac, hash_function)
            if r is not None:
                rd["HMAC/verify/nist"] = r
        if resilience:
            r = test_verify_wycheproof(hmac, hash_function)
            if r is not None:
                rd["HMAC/verify/wycheproof"] = r

    return rd


# --------------------------- Runners -------------------------------------------------
def _run_python_wrapper(
    hash_function: Hash,
    compliance: bool,
    resilience: bool,
    skip_digest: bool,
    skip_verify: bool,
):
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
):
    """Runs a wrapper."""
    match language:
        case Wrapper.PYTHON:
            return _run_python_wrapper(
                hash_function, compliance, resilience, skip_digest, skip_verify
            )
