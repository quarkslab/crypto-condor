"""Module for test ECDH implementations.

The :mod:`crypto_condor.primitives.ECDH` module can test implementations of the
:doc:`ECDH key exchange </method/ECDH>`.
"""

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
from rich.progress import track

from crypto_condor.primitives.common import Results, ResultsDict, TestInfo, TestType
from crypto_condor.vectors._ecdh.ecdh_pb2 import EcdhTest, EcdhVectors
from crypto_condor.vectors.ecdh import Curve

# --------------------------- Module --------------------------------------------------

logger = logging.getLogger(__name__)


def __dir__():  # pragma: no cover
    return [
        # Enums
        Curve.__name__,
        # Protocols
        ExchangePoint.__name__,
        ExchangeX509.__name__,
        # Test functions
        test_exchange_point.__name__,
        test_exchange_x509.__name__,
        test_wrapper.__name__,
    ]


# --------------------------- Enums ---------------------------------------------------


class PubKeyType(strenum.StrEnum):
    """The type of public key that can be used by the implementation."""

    POINT = "point"
    X509 = "x509"


class Wrapper(strenum.StrEnum):
    """Supported languages for wrappers."""

    PYTHON = "Python"


# --------------------------- Vectors -------------------------------------------------


def _load_vectors(curve: Curve, pub_type: PubKeyType) -> list[EcdhVectors]:
    """Loads vectors for a given parameter set.

    Args:
        curve:
            The elliptic curve used.
        pub_type:
            The type of public key.

    Returns:
        A list of vectors.
    """
    vectors_dir = importlib.resources.files("crypto_condor") / "vectors/_ecdh"
    sources_file = vectors_dir / "ecdh.json"
    with sources_file.open("r") as file:
        sources = json.load(file)

    vectors: list[EcdhVectors] = list()

    if curve not in sources:
        logger.warning("No ECDH test vectors for %s", str(curve))
        return vectors
    curves = sources[curve]
    if pub_type not in curves:
        logger.warning(
            "No ECDH %s test vectors for %s public keys", str(curve), str(pub_type)
        )
        return vectors

    for filename in curves[pub_type]:
        vectors_file = vectors_dir / "pb2" / filename
        _vec = EcdhVectors()
        logger.debug("Loading ECDH vectors from %s", str(filename))
        try:
            _vec.ParseFromString(vectors_file.read_bytes())
        except Exception:
            logger.error("Failed to load ECDH vectors from %s", str(filename))
            logger.debug("Exception caught while loading vectors", exc_info=True)
        vectors.append(_vec)

    return vectors


# --------------------------- Protocols -----------------------------------------------

# NOTE: The protocols are called `exchange` following cryptography's naming.
# PyCryptodome uses `key_agreement` and OpenSSL uses `derive` (e.g. `EVP_PKEY_derive`).


class ExchangePoint(Protocol):
    """Represents a function that performs ECDH using an uncompresed point.

    The function must behave live :meth:`__call__` to be tested with
    :func:`test_exchange_point`.
    """

    def __call__(self, secret: bytes, pub_point: bytes) -> bytes:
        """Performs ECDH key exchange using the peer's uncompresed point.

        Args:
            secret:
                Party A's secret value.
            pub_point:
                Party B's public key as an uncompressed point.

        Returns:
            The shared secret.
        """
        ...


class ExchangeX509(Protocol):
    """Represents a function that performs ECDH using public coordinates.

    The function must behave live :meth:`__call__` to be tested with
    :func:`test_exchange_x509`.
    """

    def __call__(self, secret: bytes, pub_key: bytes) -> bytes:
        """Performs ECDH key exchange using the peer's X509 public key.

        Args:
            secret:
                Party A's secret value.
            pub_key:
                Party B's public X509 key.

        Returns:
            The shared secret.
        """
        ...


class ECDH(Protocol):
    """Class that implements ECDH.

    Implementations use one party's private value and the other's public key to perform
    their half of the key exchange.

    There are two methods to implement which depend on the test vectors used:
    :meth:`exchange_nist` uses NIST vectors which provide the public key by its
    coordinates, while the Wycheproof vectors used by :meth:`exchange_wycheproof`
    provide them encoded with X509.

    For compliance, use :meth:`exchange_nist`.

    .. deprecated:: TODO(version)
        The test vectors have been changed so the protocols have been updated to match.
        ``ECDH`` is replaced by :class:`ExchangePoint` and :class:`ExchangeX509`.
    """

    def exchange_nist(
        self, secret: int, pub_x: int, pub_y: int, pub_key: bytes
    ) -> bytes:
        """ECDH exchange with NIST vectors.

        NIST vectors provide the public key as point coordinates. In case an
        implementation does not deal with coordinates, but at least can deal with an
        SEC1-encoded point (subset of X9.62), crypto-condor constructs and provided this
        encoded point. However, we recommend using the coordinates whenever possible.

        Args:
            secret: Party A's secret value.
            pub_x: The x-coordinate of party B's public key.
            pub_y: The y-coordinate of party B's public key.
            pub_key: The public key as a SEC1-encoded point. It does *not* provide
                information on the curve used. Constructed by crypto-condor from the
                coordinates.

        Returns:
            The shared key.
        """
        ...

    def exchange_wycheproof(self, secret: int, pub_key: bytes) -> bytes:
        """ECDH exchange with Wycheproof vectors.

        Wycheproof vectors provide the public key encoded with X509. This encoding
        includes information about the curve, along with the coordinates.

        Args:
            secret: Party A's secret value.
            pub_key: Party B's public key, encoded with X509.

        Returns:
            The shared key.
        """
        ...


# --------------------------- Dataclasses----------------------------------------------


@attrs.define
class PointData:
    """Debug data for :func:`test_exchange_point`.

    Args:
        d:
            The secret value.
        pub:
            The peer's public uncompressed point.
        ss:
            The expected shared secret.
        ret_ss:
            The returned shared secret.
    """

    d: bytes
    pub: bytes
    ss: bytes
    ret_ss: bytes | None = None

    def __str__(self) -> str:
        """Returns a string representation."""
        return f"""d = {self.d.hex()}
pub_point = {self.pub.hex()}
ss = {self.ss.hex()}
returned ss = {self.ret_ss.hex() if self.ret_ss is not None else "<none>"}
"""


@attrs.define
class X509Data:
    """Debug data for :func:`test_exchange_x509`.

    Args:
        d:
            The secret value.
        pub:
            Peer's public X509 key.
        ss:
            The expected shared secret.
        ret_ss:
            The returned shared secret.
    """

    d: bytes
    pub: bytes
    ss: bytes
    ret_ss: bytes | None = None

    def __str__(self) -> str:
        """Returns a string representation."""
        return f"""d = {self.d.hex()}
peer_key = {self.pub.hex()}
ss = {self.ss.hex()}
returned ss = {self.ret_ss.hex() if self.ret_ss is not None else "<none>"}
"""


# --------------------------- Test functions ------------------------------------------


def test_exchange_point(
    exchange: ExchangePoint,
    curve: Curve,
    *,
    compliance: bool = True,
    resilience: bool = False,
) -> ResultsDict:
    """Tests ECDH exchange with the peer's public key as an uncompressed point.

    Args:
        exchange:
            The implementation of the :protocol:`ExchangeCoord` protocol to test.
        curve:
            The elliptic curve to use.

    Keyword Args:
        compliance:
            Whether to use compliance test vectors.
        resilience:
            Whether to use resilience test vectors.

    Returns:
        A dictionary of results.

    Example:
        Let's test PyCryptodome over P-256. We need the ``ECC`` module to construct the
        keys and the ``DH`` module to actually perform the key exchange.

        >>> from Crypto.Protocol import DH
        >>> from Crypto.PublicKey import ECC

        From |cc| we import the primitive.

        >>> from crypto_condor.primitives import ECDH

        We wrap the exchange in our function to match the :protocol:`ExchangePoint`
        protocol.

        >>> def exchange_point(secret: bytes, pub_point: bytes) -> bytes:
        ...     pk = ECC.import_key(pub_point, curve_name="P-256")
        ...     d = int.from_bytes(secret)
        ...     sk = ECC.construct(curve="P-256", d=d)
        ...     return DH.key_agreement(static_priv=sk, static_pub=pk, kdf=lambda x: x)

        Then we call :func:`test_exchange_point`.

        >>> curve = ECDH.Curve.P256
        >>> rd = ECDH.test_exchange_point(exchange_point, curve)
        [P-256][NIST CAVP] Testing ExchangePoint ...
        >>> assert rd.check()

    .. versionadded:: TODO(version)
        This function roughly replaces ``test_exchange_nist``.
    """
    all_vectors = _load_vectors(curve, PubKeyType.POINT)
    rd = ResultsDict()

    test: EcdhTest
    for vectors in all_vectors:
        if not compliance and vectors.compliance:
            continue
        if not resilience and not vectors.compliance:
            continue

        res = Results.new("Tests ECDH exchange with peer point", ["curve"])
        rd.add(res, extra_values=[vectors.source])

        for test in track(
            vectors.tests, rf"\[{curve}]\[{vectors.source}] Testing ExchangePoint"
        ):
            info = TestInfo.new_from_test(test, vectors.compliance)
            data = PointData(test.d, test.peer_point, test.ss)
            try:
                ret_ss = exchange(test.d, test.peer_point)
            except NotImplementedError:
                logger.warning(
                    f"ECDH.ExchangePoint for {str(curve)} not implemented, skipped"
                )
                return rd
            except Exception as error:
                # FIXME: overly permissive.
                if test.type == "invalid":
                    info.ok(data)
                else:
                    info.fail(
                        f"Failed ECDH exchange with exception: {str(error)}", data
                    )
                res.add(info)
                logger.debug("Exception caught", exc_info=True)
                continue
            data.ret_ss = ret_ss
            if ret_ss == test.ss:
                info.ok(data)
            else:
                info.fail("Wrong shared secret", data)
            res.add(info)

    return rd


def test_exchange_nist(ecdh: ECDH, curve: Curve) -> ResultsDict:
    """Tests ECDH exchange with NIST vectors.

    Args:
        ecdh:
            The implementation of the :protocol:`ECDH` protocol to test.
        curve:
            The elliptic curve to use.

    Returns:
        A dictionary of results.

    .. versionchanged:: TODO(version)
        Returns :class:`ResultsDict` instead of :class:`Results` or None.

    .. deprecated:: TODO(version)
        The test vectors have been updated and the :protocol:`ECDH` protocol is now
        deprecated. Use :func:`test_exchange_point` and :protocol:`ExchangePoint`
        instead.
    """
    warnings.warn("Use test_exchange_point instead", DeprecationWarning, stacklevel=1)
    all_vectors = _load_vectors(curve, PubKeyType.POINT)
    rd = ResultsDict()

    if not any(vectors.source == "NIST CAVP" for vectors in all_vectors):
        logger.warning("No NIST vectors for ECDH on %s", str(curve))
        return rd

    for vectors in all_vectors:
        if not vectors.compliance:
            continue

        res = Results.new("Tests ECDH exchange with NIST vectors", ["curve"])
        rd.add(res)

        for test in track(
            vectors.tests, rf"\[{str(curve)}] Test exchange with NIST vectors"
        ):
            info = TestInfo.new_from_test(test, vectors.compliance)
            d = int.from_bytes(test.d)
            coords = test.peer_point[1:]
            x = int.from_bytes(coords[: len(coords) // 2])
            y = int.from_bytes(coords[len(coords) // 2 :])
            data = PointData(test.d, test.peer_point, test.ss)
            try:
                ret_ss = ecdh.exchange_nist(d, x, y, test.peer_point)
            except NotImplementedError:
                logger.info("ECDH.exchange_nist not implemented, test skipped")
                return rd
            except Exception as error:
                info.fail(f"Exchange failed: {str(error)}", data)
                logger.debug("Exception raised by exchange_nist", exc_info=True)
                res.add(info)
                continue
            data.ret_ss = ret_ss
            if ret_ss == test.ss:
                info.ok(data)
            else:
                info.fail("Wrong shared secret", data)
            res.add(info)

    return rd


def test_exchange_x509(
    exchange: ExchangeX509,
    curve: Curve,
    *,
    compliance: bool = True,
    resilience: bool = False,
) -> ResultsDict:
    """Tests ECDH exchange with the peer's public X509 key.

    Args:
        exchange:
            The implementation of the :protocol:`ExchangeX509` protocol to test.
        curve:
            The elliptic curve to use.

    Keyword Args:
        compliance:
            Whether to use compliance test vectors.
        resilience:
            Whether to use resilience test vectors.

    Returns:
        A dictionary of results.

    Example:
        Let's test PyCryptodome over P-256. We need the ``ECC`` module to construct the
        keys and the ``DH`` module to actually perform the key exchange.

        >>> from Crypto.Protocol import DH
        >>> from Crypto.PublicKey import ECC

        From |cc| we import the primitive.

        >>> from crypto_condor.primitives import ECDH

        We wrap the exchange in our function to match the :protocol:`ExchangeX509`
        protocol.

        >>> def exchange_x509(secret: bytes, pub_point: bytes) -> bytes:
        ...     pk = ECC.import_key(pub_point)
        ...     d = int.from_bytes(secret)
        ...     sk = ECC.construct(curve="P-256", d=d)
        ...     return DH.key_agreement(static_priv=sk, static_pub=pk, kdf=lambda x: x)

        Then we call :func:`test_exchange_x509`. There are no NIST test vectors for this
        test so we use the ``resilience`` option.

        >>> curve = ECDH.Curve.P256
        >>> rd = ECDH.test_exchange_x509(exchange_x509, curve, resilience=True)
        [P-256][Wycheproof] Testing ExchangeX509 ...
        >>> assert rd.check()
    """
    all_vectors = _load_vectors(curve, PubKeyType.X509)
    rd = ResultsDict()

    test: EcdhTest
    for vectors in all_vectors:
        if not compliance and vectors.compliance:
            continue
        if not resilience and not vectors.compliance:
            continue

        res = Results.new("Tests ECDH exchange with peer public key", ["curve"])
        rd.add(res, extra_values=[vectors.source])

        for test in track(
            vectors.tests, rf"\[{curve}]\[{vectors.source}] Testing ExchangeX509"
        ):
            info = TestInfo.new_from_test(test, vectors.compliance)
            data = X509Data(test.d, test.peer_x509, test.ss)
            try:
                ret_ss = exchange(test.d, test.peer_x509)
            except NotImplementedError:
                logger.warning(
                    f"ECDH.ExchangeX509 for {str(curve)} not implemented, skipped"
                )
                return rd
            except Exception as error:
                if test.type == "invalid":
                    info.ok(data)
                else:
                    info.fail(
                        f"Failed ECDH exchange with exception: {str(error)}", data
                    )
                res.add(info)
                logger.debug("Exception caught", exc_info=True)
                continue
            data.ret_ss = ret_ss
            if ret_ss == test.ss:
                info.ok(data)
            else:
                info.fail("Wrong shared secret", data)
            res.add(info)

    return rd


def test_exchange_wycheproof(ecdh: ECDH, curve: Curve) -> ResultsDict:
    """Tests ECDH.exchange with Wycheproof vectors.

    Wycheproof vectors provide X509-encoded public keys.

    Args:
        ecdh:
            The implementation to test.
        curve:
            The elliptic curve to use.

    Returns:
        A dictionary of results.

    .. versionchanged:: TODO(version)
        Returns :class:`ResultsDict` instead of :class:`Results` or None.

    .. deprecated:: TODO(version)
        The test vectors have been updated and the :protocol:`ECDH` protocol is now
        deprecated. Use :func:`test_exchange_x509` and :protocol:`ExchangeX509`
        instead.
    """
    warnings.warn("Use test_exchange_x509 instead", DeprecationWarning, stacklevel=1)

    all_vectors = _load_vectors(curve, PubKeyType.X509)
    rd = ResultsDict()

    if not any(vectors.source == "Wycheproof" for vectors in all_vectors):
        logger.warning("No Wycheproof vectors for ECDH on %s", str(curve))
        return rd

    test: EcdhTest
    for vectors in all_vectors:
        if vectors.compliance:
            continue

        res = Results.new("Tests ECDH exchange with Wycheproof vectors", ["curve"])
        rd.add(res)

        for test in track(
            vectors.tests, rf"\[{str(curve)}] Test exchange with Wycheproof vectors"
        ):
            info = TestInfo.new_from_test(test, vectors.compliance)
            secret = int.from_bytes(test.d)
            data = X509Data(test.d, test.peer_x509, test.ss)
            try:
                ret_ss = ecdh.exchange_wycheproof(secret, test.peer_x509)
            except NotImplementedError:
                logger.info("ECDH.exchange_wycheproof not implemented, test skipped")
                return rd
            except Exception as error:
                if test.type == TestType.VALID:
                    info.fail(f"Exchange failed: {str(error)}", data)
                else:
                    # FIXME: overly permissive.
                    info.ok(data)
                logger.debug("Exception raised by exchange_wycheproof", exc_info=True)
                res.add(info)
                continue
            data.ret_ss = ret_ss
            is_same_ss = ret_ss == test.ss
            match (test.type, is_same_ss):
                case (TestType.VALID, True) | (TestType.INVALID, False):
                    info.ok(data)
                case (TestType.VALID, False):
                    info.fail("Implementation returned wrong shared secret", data)
                case (TestType.INVALID, True):
                    # We should not get here since the invalid public key should've
                    # raised an error when calling exchange.
                    info.fail(
                        (
                            "Implementation returned a shared secret"
                            " from an invalid public key"
                        ),
                        data,
                    )
                case (TestType.ACCEPTABLE, (True | False)):
                    info.ok(data)
            res.add(info)

    return rd


def test_exchange(
    ecdh: ECDH, curve: Curve, *, compliance: bool = True, resilience: bool = False
) -> ResultsDict:
    """Tests an implementation of ECDH.

    Args:
        ecdh:
            The implementation to test. It must conform to the :protocol:`ECDH`
            protocol.
        curve:
            The elliptic curve to use.

    Keyword Args:
        compliance:
            Whether to use NIST vectors.
        resilience:
            Whether to use Wycheproof vectors.

    Returns:
        A dictionary of results.

    Notes:
        Internally calls the :func:`test_exchange_nist` and
        :func:`test_exchange_wycheproof` functions.

    .. versionchanged:: TODO(version)
        Returns :class:`ResultsDict` instead of :class:`Results` or None.

    .. deprecated:: TODO(version)
        The test vectors have been updated and the :protocol:`ECDH` protocol is now
        deprecated. Use :func:`test_exchange_point` and :func:`test_exchange_x509`
        instead.
    """
    warnings.warn(
        "Use test_exchange_point and test_exchange_x509 instead",
        DeprecationWarning,
        stacklevel=1,
    )
    rd = ResultsDict()
    if not compliance and not resilience:
        logger.warning("compliance and resilience disabled, nothing to test")
        return rd
    if compliance:
        rd |= test_exchange_nist(ecdh, curve)
    if resilience:
        rd |= test_exchange_wycheproof(ecdh, curve)
    return rd


# --------------------------- Runners -------------------------------------------------


def test_wrapper_python(
    wrapper: Path, compliance: bool, resilience: bool
) -> ResultsDict:
    """Runs a Python wrapper of ECDH.

    Args:
        wrapper:
            The wrapper to test. The path must be valid.
        compliance:
            Whether to use compliance test vectors.
        resilience:
            Whether to use resilience test vectors.

    Returns:
        The results of :func:`test_exchange_point` and :func:`test_exchange_x509` in a
        single dictionary.

    Raises:
        ModuleNotFoundError:
            If the wrapper could not be loaded.
    """
    logger.info("Testing Python ECDH wrapper: %s", str(wrapper.name))
    sys.path.insert(0, str(wrapper.parent.absolute()))
    already_imported = wrapper.stem in sys.modules.keys()
    try:
        ecdh_wrapper = importlib.import_module(wrapper.stem)
    except ModuleNotFoundError as error:
        logger.error("Can't import wrapper: %s", str(error))
        raise
    if already_imported:
        logger.debug("Reloading ECDH wrapper module %s", wrapper.stem)
        ecdh_wrapper = importlib.reload(ecdh_wrapper)

    rd = ResultsDict()

    for function, _ in inspect.getmembers(ecdh_wrapper, inspect.isfunction):
        match function.split("_"):
            case ["CC", "ECDH", "exchange", "point", _curve]:
                logger.info("Found CC_ECDH function %s", function)
                try:
                    curve = Curve.from_name(_curve)
                except ValueError as error:
                    logger.error("%s, test skipped", str(error))
                    continue
                rd |= test_exchange_point(
                    getattr(ecdh_wrapper, function),
                    curve,
                    compliance=compliance,
                    resilience=resilience,
                )
            case ["CC", "ECDH", "exchange", "x509", _curve]:
                logger.info("Found CC_ECDH function %s", function)
                try:
                    curve = Curve.from_name(_curve)
                except ValueError as error:
                    logger.error("%s, test skipped", str(error))
                    continue
                rd |= test_exchange_x509(
                    getattr(ecdh_wrapper, function),
                    curve,
                    compliance=compliance,
                    resilience=resilience,
                )
            case ["CC", "ECDH", *_]:
                logger.warning("Ignored invalid CC_ECDH function %s", function)
                continue
            case _:
                pass

    # NOTE: We no longer get the curve from the CLI arguments and there is no way of
    # inferring it. We could add the curve to the name of the class, updating its
    # interface, but since it's already deprecated it does not make sense to do so.
    # Instead, we still check for the presence of the class in the wrapper and warn
    # about its usage.
    # TODO: remove this when removing the CC_ECDH protocol.

    def _has_cc_ecdh(item) -> bool:
        name, _ = item
        return name == "CC_ECDH"

    classes = inspect.getmembers(ecdh_wrapper, inspect.isclass)

    if filter(_has_cc_ecdh, classes):
        logger.error("The CC_ECDH class can no longer be tested with a wrapper")
        logger.warning(
            "A new wrapper interface was added for ECDH. It is still possible to test"
            " the class through the Python API. Please refer to the documentation for"
            " the wrapper interface for an example of both."
        )

    return rd


def test_wrapper(
    wrapper: Path,
    compliance: bool,
    resilience: bool,
) -> ResultsDict:
    """Runs a ECDH wrapper.

    Args:
        wrapper:
            The wrapper to test.
        compliance:
            Whether to use NIST vectors.
        resilience:
            Whether to use Wycheproof vectors.

    Returns:
        The results of :func:`test_exchange_point` and :func:`test_exchange_x509` in a
        single dictionary.

    Raises:
        FileNotFoundError:
            If the wrapper could not be found.
        ModuleNotFoundError:
            If the wrapper could not be loaded.
    """
    if not wrapper.is_file():
        raise FileNotFoundError(f"ECDH wrapper not found: {str(wrapper)}")
    match wrapper.suffix:
        case ".py":
            return test_wrapper_python(wrapper, compliance, resilience)
        case _:
            raise ValueError(
                f"There is no runner defined for '{wrapper.suffix}' wrappers"
            )


# --------------------------- Lib hook functions --------------------------------------


def _test_harness_exchange_point(
    ffi: cffi.FFI, lib, function: str, curve: Curve, compliance: bool, resilience: bool
) -> ResultsDict:
    logger.info("Testing harness function %s", function)

    ffi.cdef(
        f"""int {function}(uint8_t ss[512], size_t *ss_size,
                const uint8_t *secret, const size_t secret_size,
                const uint8_t *point, const size_t point_size);
        """
    )

    exchange = getattr(lib, function)

    # We use a buffer large enough for any shared secret to avoid allocation by the
    # callee. The uint8_t pointer will be used to get the actual size of the shared
    # secret.
    c_ss = ffi.new("uint8_t[512]")
    c_ss_size = ffi.new("size_t *")

    def _exchange(secret: bytes, pub_point: bytes) -> bytes:
        c_secret = ffi.new("uint8_t[]", secret)
        c_secret_size = len(secret)
        c_pub = ffi.new("uint8_t[]", pub_point)
        c_pub_size = len(pub_point)
        rc = exchange(c_ss, c_ss_size, c_secret, c_secret_size, c_pub, c_pub_size)
        if rc != 1:
            raise ValueError(f"{function} failed with code {rc}")
        return bytes(c_ss)[: c_ss_size[0]]

    return test_exchange_point(
        _exchange, curve, compliance=compliance, resilience=resilience
    )


def _test_harness_exchange_x509(
    ffi: cffi.FFI, lib, function: str, curve: Curve, compliance: bool, resilience: bool
) -> ResultsDict:
    logger.info("Testing harness function %s", function)

    ffi.cdef(
        f"""int {function}(uint8_t ss[512], size_t *ss_size,
                const uint8_t *secret, const size_t secret_size,
                const uint8_t *pub, const size_t pub_size);
        """
    )

    exchange = getattr(lib, function)

    # We use a buffer large enough for any shared secret to avoid allocation by the
    # callee. The uint8_t pointer will be used to get the actual size of the shared
    # secret.
    c_ss = ffi.new("uint8_t[512]")
    c_ss_size = ffi.new("size_t *")

    def _exchange(secret: bytes, pub_key: bytes) -> bytes:
        c_secret = ffi.new("uint8_t[]", secret)
        c_secret_size = len(secret)
        c_pub = ffi.new("uint8_t[]", pub_key)
        c_pub_size = len(pub_key)
        rc = exchange(c_ss, c_ss_size, c_secret, c_secret_size, c_pub, c_pub_size)
        if rc != 1:
            raise ValueError(f"{function} failed with code {rc}")
        return bytes(c_ss)[: c_ss_size[0]]

    return test_exchange_x509(
        _exchange, curve, compliance=compliance, resilience=resilience
    )


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

    for function in functions:
        match function.split("_"):
            case ["CC", "ECDH", "exchange", "point", _curve]:
                try:
                    curve = Curve.from_name(_curve)
                except ValueError:
                    logger.error(
                        "Invalid curve %s for ECDH, skipped %s", _curve, function
                    )
                    continue
                rd |= _test_harness_exchange_point(
                    ffi, lib, function, curve, True, True
                )
            case ["CC", "ECDH", "exchange", "x509", _curve]:
                try:
                    curve = Curve.from_name(_curve)
                except ValueError:
                    logger.error(
                        "Invalid curve %s for ECDH, skipped %s", _curve, function
                    )
                    continue
                rd |= _test_harness_exchange_x509(ffi, lib, function, curve, True, True)
            case ["CC", "ECDH", *_]:
                logger.warning("Invalid CC_ECDH function %s, skipped", function)
                continue
            case _:
                pass

    return rd
