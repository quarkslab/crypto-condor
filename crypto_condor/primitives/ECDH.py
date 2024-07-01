"""Module for test ECDH implementations.

The :mod:`crypto_condor.primitives.ECDH` module can test implementations of the
:doc:`ECDH key exchange </method/ECDH>` with the :func:`test_exchange` function.
"""

import importlib
import logging
import sys
from pathlib import Path
from typing import Protocol

import attrs
import strenum
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from rich.progress import track

from crypto_condor.primitives.common import Results, ResultsDict, TestInfo, TestType
from crypto_condor.vectors._ECDH.ECDH_pb2 import EcdhNistVectors, EcdhWycheproofVectors

# --------------------------- Module --------------------------------------------------

logger = logging.getLogger(__name__)


def __dir__():  # pragma: no cover
    return [
        # Enums
        Curve.__name__,
        Wrapper.__name__,
        # Protocols
        ECDH.__name__,
        # Tests
        test_exchange.__name__,
        # Internal tests
        test_exchange_nist.__name__,
        test_exchange_wycheproof.__name__,
        # Vectors
        EcdhVectors.__name__,
        # Runners
        run_wrapper.__name__,
    ]


# --------------------------- Enums ---------------------------------------------------


class Curve(strenum.StrEnum):
    """Elliptic curves supported for ECDH.

    As shown below, not all curves have NIST and Wycheproof vectors. To determine
    whether a curve has a specific source programmatically, see :attr:`nist` and
    :attr:`wycheproof`.

    .. csv-table:: Test vector sources
        :header: Curve, NIST, Wycheproof

        "P-224, P-256, P-384, P-521", |Y|, |Y|
        "B-283, B-409, B-571", |Y|, |Y|
        "K-283, K-409, K-571", |Y|, |Y|
        "P-192", |Y|, |N|
        "B-163, B-233", |Y|, |N|
        "K-163, K-233", |Y|, |N|
        "secp256k1", |N|, |Y|
        "brainpool*", |N|, |Y|
    """

    def __init__(self, value):
        """Overrides __init__ to add custom properties."""
        match value:
            case "P-224" | "P-256" | "P-384" | "P-521":
                self._nist_, self._wycheproof_ = True, True
            case "B-283" | "B-409" | "B-571":
                self._nist_, self._wycheproof_ = True, True
            case "K-283" | "K-409" | "K-571":
                self._nist_, self._wycheproof_ = True, True
            case "P-192":
                self._nist_, self._wycheproof_ = True, False
            case "B-163" | "B-233":
                self._nist_, self._wycheproof_ = True, False
            case "K-163" | "K-233":
                self._nist_, self._wycheproof_ = True, False
            case (
                "brainpoolP224r1"
                | "brainpoolP256r1"
                | "brainpoolP320r1"
                | "brainpoolP384r1"
                | "brainpoolP512r1"
            ):
                self._nist_, self._wycheproof_ = False, True
            case "secp256k1":
                self._nist_, self._wycheproof_ = False, True
        match value:
            case "P-192":
                self._ec_curve_ = ec.SECP192R1
            case "P-224":
                self._ec_curve_ = ec.SECP224R1
            case "P-256":
                self._ec_curve_ = ec.SECP256R1
            case "P-384":
                self._ec_curve_ = ec.SECP384R1
            case "P-521":
                self._ec_curve_ = ec.SECP521R1
            case "K-163":
                self._ec_curve_ = ec.SECT163K1
            case "K-233":
                self._ec_curve_ = ec.SECT233K1
            case "K-283":
                self._ec_curve_ = ec.SECT283K1
            case "K-409":
                self._ec_curve_ = ec.SECT409K1
            case "K-571":
                self._ec_curve_ = ec.SECT571K1
            case "B-163":
                # R2 is *not* a typo: see https://neuromancer.sk/std/nist/B-163
                self._ec_curve_ = ec.SECT163R2
            case "B-233":
                self._ec_curve_ = ec.SECT233R1
            case "B-283":
                self._ec_curve_ = ec.SECT283R1
            case "B-409":
                self._ec_curve_ = ec.SECT409R1
            case "B-571":
                self._ec_curve_ = ec.SECT571R1
            case _:
                self._ec_curve_ = None

    P192 = "P-192"
    P224 = "P-224"
    P256 = "P-256"
    P384 = "P-384"
    P521 = "P-521"
    K163 = "K-163"
    K233 = "K-233"
    K283 = "K-283"
    K409 = "K-409"
    K571 = "K-571"
    B163 = "B-163"
    B233 = "B-233"
    B283 = "B-283"
    B409 = "B-409"
    B571 = "B-571"
    BRAINPOOLP224R1 = "brainpoolP224r1"
    BRAINPOOLP256R1 = "brainpoolP256r1"
    BRAINPOOLP320R1 = "brainpoolP320r1"
    BRAINPOOLP384R1 = "brainpoolP384r1"
    BRAINPOOLP512R1 = "brainpoolP512r1"
    SECP256K1 = "secp256k1"

    @property
    def nist(self) -> bool:
        """True if there are NIST vectors for this curve."""
        return self._nist_

    @property
    def wycheproof(self) -> bool:
        """True if there are Wycheproof vectors for this curve."""
        return self._wycheproof_

    @property
    def ec_curve(self) -> ec.EllipticCurve | None:
        """Returns an instance of the elliptic curve from :mod:`cryptography`.

        This property is intended for :func:`test_exchange_nist` to serialize the EC
        point to SEC1 format. As such, only curves for which there are NIST vectors are
        returned. Returns None otherwise.
        """
        return self._ec_curve_()


class Wrapper(strenum.StrEnum):
    """Supported languages for wrappers."""

    PYTHON = "Python"


# --------------------------- Vectors -------------------------------------------------


@attrs.define
class EcdhVectors:
    """Test vectors for ECDH.

    Do not instantiate directly, use :meth:`load`.

    Available vectors are defined by :enum:`Curve`.

    Args:
        curve: The elliptic curve used for the test vectors.
        nist: NIST test vectors if they exist for the given curve, None otherwise.
        wycheproof: Wycheproof test vectors if they exist for the given curve, None
            otherwise.
    """

    curve: Curve
    nist: EcdhNistVectors | None
    wycheproof: EcdhWycheproofVectors | None

    @classmethod
    def load(cls, curve: Curve, *, compliance: bool = True, resilience: bool = True):
        """Loads ECDH test vectors.

        Args:
            curve: The elliptic curve to get vectors for.

        Keyword Args:
            compliance: Whether to load NIST vectors.
            resilience: Whether to load Wycheproof vectors.
        """
        vectors_dir = importlib.resources.files("crypto_condor") / "vectors/_ECDH/dat"
        nist: EcdhNistVectors | None = None
        wycheproof: EcdhWycheproofVectors | None = None

        if compliance and curve.nist:
            vectors_file = vectors_dir / f"nist_{str(curve)}.dat"
            nist = EcdhNistVectors()
            try:
                nist.ParseFromString(vectors_file.read_bytes())
            except Exception:
                logger.error("Error loading NIST vectors")
                logger.debug("Exception caught", exc_info=True)
                nist = None

        if resilience and curve.wycheproof:
            # Works when using str(curve) as we already normalized the names on the
            # import script.
            vectors_file = vectors_dir / f"wycheproof_{str(curve)}_eckey.dat"
            wycheproof = EcdhWycheproofVectors()
            try:
                wycheproof.ParseFromString(vectors_file.read_bytes())
            except Exception:
                logger.error("Error loading Wycheproof vectors")
                logger.debug("Exception caught", exc_info=True)
                wycheproof = None

        return cls(curve, nist, wycheproof)


# --------------------------- Protocols -----------------------------------------------


# The methods are called `exchange` following cryptography's naming. PyCryptodome use
# `key_agreement` and OpenSSL uses `derive` e.g `EVP_PKEY_derive`.
class ECDH(Protocol):
    """Class that implements ECDH.

    Implementations use one party's private value and the other's public key to perform
    their half of the key exchange.

    There are two methods to implement which depend on the test vectors used:
    :meth:`exchange_nist` uses NIST vectors which provide the public key by its
    coordinates, while the Wycheproof vectors used by :meth:`exchange_wycheproof`
    provide them encoded with X509.

    For compliance, use :meth:`exchange_nist`.
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
class EcdhNistData:
    """Test data for :func:`test_exchange_nist`."""

    secret: int
    px: int
    py: int
    shared: bytes
    result: bytes | None = None

    def __str__(self) -> str:
        """Returns a string representation."""
        return f"""secret = {self.secret}
pub_x = {self.px}
pub_y = {self.py}
expected shared = {self.shared.hex()}
returned shared = {self.result.hex() if self.result else '<none>'}
"""


@attrs.define
class EcdhWycheproofData:
    """Test data for :func:`test_exchange_wycheproof`."""

    secret: int
    public: bytes
    shared: bytes
    result: bytes | None = None

    def __str__(self) -> str:
        """Returns a string representation."""
        return f"""secret = {self.secret}
pubkey = {self.public.hex()}
expected shared = {self.shared.hex()}
returned shared = {self.result.hex() if self.result else '<none>'}
"""


# --------------------------- Test functions ------------------------------------------


def test_exchange_nist(ecdh: ECDH, curve: Curve) -> Results | None:
    """Tests ECDH exchange with NIST vectors.

    Args:
        ecdh: The implementation of the :protocol:`ECDH` protocol to test.
        curve: The elliptic curve to use.

    Returns:
        The results of testing the implementation by computing the shared secret with
        the implementation and comparing it to the expected one. None if there are no
        NIST vectors for the given curve or the ``exchange_nist`` method is not
        implemented.
    """
    vectors = EcdhVectors.load(curve, resilience=False)
    if vectors.nist is None:
        logger.warning("No NIST vectors for ECDH on %s", str(curve))
        return None
    ec_curve = curve.ec_curve
    if ec_curve is None:
        logger.error(
            "Program error: EC instance not found for NIST vectors, returning None"
        )
        return None

    results = Results.new("Tests ECDH exchange with NIST vectors", ["curve"])
    for test in track(vectors.nist.tests, "[NIST] Exchanging keys"):
        info = TestInfo.new(test.count, TestType.VALID, ["Compliance"])
        d = int.from_bytes(test.own_d, "big")
        x = int.from_bytes(test.peer_x, "big")
        y = int.from_bytes(test.peer_y, "big")
        data = EcdhNistData(d, x, y, test.z)
        point = ec.EllipticCurvePublicNumbers(x, y, ec_curve)
        pk = point.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        try:
            shared = ecdh.exchange_nist(d, x, y, pk)
        except NotImplementedError:
            logger.info("Method not implemented, test skipped")
            return None
        except Exception as error:
            info.fail(f"Exchange failed: {str(error)}", data)
            logger.debug("Exception raised by exchange_nist", exc_info=True)
            results.add(info)
            continue
        if shared == test.z:
            data.result = shared
            info.ok(data)
        else:
            info.fail("Wrong shared secret returned", data)
        results.add(info)
    return results


def test_exchange_wycheproof(ecdh: ECDH, curve: Curve) -> Results | None:
    """Tests ECDH.exchange with Wycheproof vectors.

    Wycheproof vectors provide X509-encoded public keys.

    Args:
        ecdh: The implementation to test.
        curve: The elliptic curve to use.

    Returns:
        The results of testing the implementation by computing the shared secret and
        comparing it to the expected one, or None if there are no Wycheproof vectors for
        the given curve.
    """
    vectors = EcdhVectors.load(curve, compliance=False)
    if vectors.wycheproof is None:
        logger.warning("No Wycheproof vectors for ECDH on %s", str(curve))
        return None

    results = Results.new("Test ECDH exchange with Wycheproof vectors", ["curve"])
    for group in track(vectors.wycheproof.groups, "[Wycheproof] Exchanging keys"):
        for test in group.tests:
            test_type = TestType(test.result)
            info = TestInfo.new(test.id, test_type, test.flags, test.comment)
            secret = int.from_bytes(test.secret, "big")
            data = EcdhWycheproofData(secret, test.public, test.shared)
            try:
                shared = ecdh.exchange_wycheproof(secret, test.public)
            except NotImplementedError:
                logger.info("Method not implemented, test skipped")
                return None
            except Exception as error:
                info.fail(f"Exchange failed: {str(error)}", data)
                logger.debug("Exception raised by exchange_wycheproof", exc_info=True)
                results.add(info)
                continue
            data.result = shared
            res = shared == test.shared
            data.result = shared
            match (test_type, res):
                case (TestType.VALID, True, TestType.INVALID, False):
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
            results.add(info)
    return results


def test_exchange(
    ecdh: ECDH, curve: Curve, *, compliance: bool = True, resilience: bool = False
) -> ResultsDict:
    """Tests an implementation of ECDH.

    Args:
        ecdh: The implementation to test. It must conform to the :protocol:`ECDH`
            protocol.
        curve: The elliptic curve to use. For available test vectors, see :enum:`Curve`.

    Keyword Args:
        compliance: Whether to use NIST vectors.
        resilience: Whether to use Wycheproof vectors.

    Returns:
        The results of testing with NIST and Wycheproof vectors, depending on the
        options used. Dictionary keys are ``ECDH/test_exchange_nist/<curve name>`` and
        ``ECDH/test_exchange_wycheproof/<curve name>``. The dictionary can be empty if
        there are no vectors from the sources selected.

    Notes:
        Internally calls the :func:`test_exchange_nist` and
        :func:`test_exchange_wycheproof` functions.

    Example:
        Let's test PyCryptodome's implementation with NIST vectors on the P-192 curve.

        >>> from Crypto.Protocol import DH
        >>> from Crypto.PublicKey import ECC
        >>> # Build a class that conforms to the ECDH protocol.
        >>> class MyEcdh:
        ...     def exchange_nist(
        ...         self,
        ...         secret: int,
        ...         pub_x: int,
        ...         pub_y: int,
        ...         pub_key: bytes
        ...     ) -> bytes:
        ...         # We can use the coordinates directly.
        ...         pk = ECC.construct(curve="P-192", point_x=pub_x, point_y=pub_y)
        ...         # And we only need the secret value to construct the private key.
        ...         sk = ECC.construct(curve="P-192", d=secret)
        ...         # We want the raw shared secret, so we use a KDF that does nothing.
        ...         shared = DH.key_agreement(
        ...             static_priv=sk,
        ...             static_pub=pk,
        ...             kdf=lambda x: x,
        ...         )
        ...         return shared
        ...     def exchange_wycheproof(
        ...         self,
        ...         secret,
        ...         public_key,
        ...     ) -> bytes:
        ...         # We define the Wycheproof way to ensure the test is skipped if the
        ...         # exception is raised.
        ...         raise NotImplementedError

        We can now test this implementation:

        >>> from crypto_condor.primitives import ECDH
        >>> curve = ECDH.Curve("P-192")
        >>> rdict = ECDH.test_exchange(MyEcdh(), curve)
        [NIST] ...

        We can check the result of testing with the NIST vectors.

        >>> res = rdict["ECDH/test_exchange_nist/P-192"]
        >>> assert res.check()
    """
    rdict = ResultsDict()
    if not compliance and not resilience:
        logger.warning("compliance and resilience disabled, nothing to test")
        return rdict
    if compliance:
        rdict.add(test_exchange_nist(ecdh, curve))
    if resilience:
        rdict.add(test_exchange_wycheproof(ecdh, curve))
    return rdict


# --------------------------- Runners -------------------------------------------------


def run_wrapper_python(
    wrapper: Path, curve: Curve, compliance: bool, resilience: bool
) -> ResultsDict:
    """Runs a Python wrapper of ECDH.

    Imports the wrapper script and searches for a class named CC_ECDH. If found, it is
    passed to :func:`test_exchange` with the corresponding options.

    Args:
        wrapper: The wrapper to test. The path must be valid.
        curve: The elliptic curve to use.
        compliance: Whether to use NIST vectors.
        resilience: Whether to use Wycheproof vectors.

    Returns:
        The results returned by :func:`test_exchange`.

    Raises:
        ModuleNotFoundError: If the module could not be loaded.
    """
    logger.info("Python ECDH wrapper: %s", str(wrapper.name))
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
    ecdh = ecdh_wrapper.CC_ECDH()
    return test_exchange(ecdh, curve)


def run_wrapper(
    wrapper: Path,
    lang: Wrapper,
    curve: Curve,
    compliance: bool = True,
    resilience: bool = False,
) -> ResultsDict:
    """Runs a ECDH wrapper.

    Args:
        wrapper: The wrapper to test.
        lang: The language of the wrapper.
        curve: The elliptic curve to use.
        compliance: Whether to use NIST vectors.
        resilience: Whether to use Wycheproof vectors.

    Returns:
        The results of :func:`test_exchange`.

    Raises:
        FileNotFoundError: If the wrapper could not be found.
        ValueError: If lang or curve are not valid values.

    Example:
        >>> from crypto_condor.primitives import ECDH
        >>> from pathlib import Path
        >>> my_wrapper = Path("my_wrapper.py")
        >>> lang = ECDH.Wrapper.PYTHON
        >>> curve = ECDH.Curve.P192
        >>> rdict = ECDH.run_wrapper(my_wrapper, lang, curve)  # doctest: +SKIP
    """
    if not wrapper.is_file():
        raise FileNotFoundError(f"ECDH wrapper not found: {str(wrapper)}")
    match lang:
        case Wrapper.PYTHON:
            return run_wrapper_python(wrapper, curve, compliance, resilience)
        case _:
            raise ValueError("There is no runner defined for the %s wrapper" % lang)
