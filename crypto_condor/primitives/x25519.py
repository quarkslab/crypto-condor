"""Module for x25519."""

import inspect
import json
import logging
from importlib import resources
from pathlib import Path
from typing import Protocol

import attrs
import strenum
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from rich.progress import track

from crypto_condor.primitives.common import (
    Results,
    ResultsDict,
    TestInfo,
    TestType,
    _load_python_harness,
)
from crypto_condor.vectors._x25519.x25519_pb2 import (
    X25519Test,
    X25519Vectors,
)

# --------------------------- Module --------------------------------------------------

logger = logging.getLogger(__name__)


def __dir__():  # pragma: no cover
    return [
        # Enums
        Wrapper.__name__,
        # Protocols
        Exchange.__name__,
        # Test functions
        test_exchange.__name__,
        # Runners
        test_harness.__name__,
        test_harness_python.__name__,
    ]


# --------------------------- Enums ---------------------------------------------------


class Wrapper(strenum.StrEnum):
    """Supported languages for wrappers."""

    PYTHON = "Python"


# --------------------------- Vectors -------------------------------------------------


def _load_vectors(compliance: bool, resilience: bool) -> list[X25519Vectors]:
    """Loads test vectors.

    Returns:
        A list of vectors.
    """
    vectors_dir = resources.files("crypto_condor") / "vectors/_x25519"
    vectors = list()

    sources_file = vectors_dir / "x25519.json"
    with sources_file.open("r") as file:
        sources = json.load(file)

    for filename in sources:
        vectors_file = vectors_dir / "pb2" / filename
        _vec = X25519Vectors()
        logger.debug("Loading x25519 vectors from %s", str(filename))
        try:
            _vec.ParseFromString(vectors_file.read_bytes())
        except Exception:
            logger.error("Failed to load x25519 vectors from %s", str(filename))
            logger.debug("Exception caught while loading vectors", exc_info=True)
            continue
        if _vec.compliance and compliance:
            vectors.append(_vec)
        if not _vec.compliance and resilience:
            vectors.append(_vec)

    if not vectors:
        logger.error(
            "No X25519 test vectors loaded for compliance=%s, resilience=%s",
            compliance,
            resilience,
        )

    return vectors


# --------------------------- Protocols -----------------------------------------------


class Exchange(Protocol):
    """Represents an X25519 key exchange."""

    def __call__(self, secret_key: bytes, peer_key: bytes) -> bytes:  # pragma: no cover
        """Performs an X25519 key exchange.

        Args:
            secret_key:
                "Our" secret key.
            peer_key:
                The "peer" public key.

        Returns:
            The resulting shared secret.
        """
        ...


# --------------------------- Dataclasses----------------------------------------------


@attrs.define
class ExchangeData:
    """Debug data for :func:`test_exchange`."""

    sk: bytes
    pk: bytes
    shared: bytes
    ret_shared: bytes | None

    def __str__(self):
        """Returns a string representation of the fields in use."""
        return f"""secret = {self.sk.hex()}
public = {self.pk.hex()}
shared = {self.shared.hex()}
returned_shared = {self.ret_shared.hex() if self.ret_shared else "<none>"}
"""

    @classmethod
    def from_test(cls, test: X25519Test):
        """Returns a new instance from a test."""
        return cls(test.sk, test.pk, test.shared, None)


# -------------------------------------------------------------------------------------
# Test functions
# -------------------------------------------------------------------------------------


def test_exchange(
    exchange: Exchange, compliance: bool, resilience: bool
) -> ResultsDict:
    """Tests a function implementing the X25519 key exchange.

    Calls the `exchange` function to perform a X25519 key exchange.

    Compliance test vectors from RFC 7749 are all valid, the implementation is expected
    to return the correct shared secret.

    Resilience test vectors from Wycheproof are either valid or acceptable. The latter
    include edge cases that are not necessarily forbidden by the RFC.

    Args:
        exchange:
            The function to test. Must follow :protocol:`Exchange`.
        compliance:
            Whether to use compliance test vectors.
        resilience:
            Whether to use resilience test vectors.
    """
    rd = ResultsDict()

    test_vectors = _load_vectors(compliance, resilience)
    if not test_vectors:
        return rd

    test: X25519Test
    for vectors in test_vectors:
        results = Results.new("Tests an X25519 key exchange", [], vectors)
        rd.add(results, extra_values=[vectors.source])

        for test in track(
            vectors.tests, rf"\[X25519]\[{vectors.source}] Test exchange"
        ):
            data = ExchangeData.from_test(test)
            info = TestInfo.new_from_test(test, vectors.compliance, data)

            try:
                data.ret_shared = exchange(data.sk, data.pk)
            except NotImplementedError:
                logger.warning("X25519 exchange not implemented, test skipped")
                return rd
            except Exception as error:
                logger.debug("Caught exception from X25519 exchange", exc_info=True)
                info.fail(f"Exception raised: {str(error)}")
                results.add(info)
                continue

            match (test.type, data.ret_shared == data.shared):
                case (TestType.VALID, True):
                    info.ok()
                case (TestType.VALID, False):
                    info.fail("Wrong shared secret")
                case (TestType.INVALID, _):
                    # TODO: currently no invalid test vectors are available.
                    pass
                case (TestType.ACCEPTABLE, True):
                    # TODO: do we really want to accept all tags?
                    info.ok()
                case (TestType.ACCEPTABLE, False):
                    info.fail()
                case (TestType(), _):
                    # Recover the type of the returned value then remove the value from
                    # data to avoid calling hex() on an object that most likely does not
                    # have the method.
                    ret_type = type(data.ret_shared)
                    data.ret_shared = None
                    info.fail(f"Invalid value returned: expected bytes, got {ret_type}")

            results.add(info)

    return rd


def test_output_exchange(output: Path) -> ResultsDict:
    """Tests the output of a function that perform X25519 key exchanges.

    The private and public keys are used to perform the exchange internally and compare
    the result with the output of the function. The test passes if all shared secrets
    are equal.

    Format:

        - One line per signature operation.
        - All values are encoded in hexadecimal.
        - Values are separated by a single forward slash, no spaces.
        - Lines are separated by a single newline.
        - The order of arguments is:

            .. code::

                secret_key / public_key / shared_secret

    Args:
        output:
            The path to the output file.

    Returns:
        A dictionary containing a single :class:`Results`.
    """
    rd = ResultsDict()

    try:
        with output.open("r") as fp:
            lines = fp.readlines()
    except (IOError, FileNotFoundError):
        logger.exception("Failed to read file %s", str(output))
        return rd

    res = Results.new(
        "Tests the output of a function that perform X25519 key exchanges", ["output"]
    )
    rd.add(res)

    for index, line in enumerate(lines, 1):
        if line.startswith("#"):
            continue
        line = line.strip()
        match line.split("/"):
            case [_sk, _pk, _ss]:
                sk, pk, ss = map(bytes.fromhex, (_sk, _pk, _ss))
            case _:
                logger.error("Failed to parse line %d (expected 3 values)", index)
                continue

        info = TestInfo.new(index, TestType.VALID, ["UserInput"])
        try:
            skey = X25519PrivateKey.from_private_bytes(sk)
            pkey = X25519PublicKey.from_public_bytes(pk)
            ret_ss = skey.exchange(pkey)
        except Exception as error:
            # TODO: catch specific exceptions for better debugging
            logger.exception("Failed to perform X25519 exchange")
            info.fail(f"Fail to perform exchange: {error}")
        else:
            if ret_ss == ss:
                info.ok()
            else:
                info.fail("Wrong shared secret")
        finally:
            res.add(info)

    return rd


# -------------------------------------------------------------------------------------
# Harnesses
# -------------------------------------------------------------------------------------


def test_harness_python(
    harness: Path, compliance: bool, resilience: bool
) -> ResultsDict:
    """Tests a x25519 Python harness.

    Args:
        harness:
            A path to the harness to test.
        compliance:
            Whether to use compliance test vectors.
        resilience:
            Whether to use resilience test vectors.
    """
    rd = ResultsDict()

    module_harness = _load_python_harness(harness)
    if module_harness is None:
        return rd

    for funcname, _ in inspect.getmembers(module_harness, inspect.isfunction):
        func = getattr(module_harness, funcname)
        match funcname.split("_"):
            case ["CC", "x25519", "exchange"]:
                rd |= test_exchange(func, compliance, resilience)
            case ["CC", "x25519", *_]:
                logger.warning("Invalid function CC_x25519 %s", funcname)
                continue

    return rd


def test_harness(harness: Path, compliance: bool, resilience: bool) -> ResultsDict:
    """Tests a x25519 harness.

    Args:
        harness:
            The harness to test.
        compliance:
            Whether to use compliance test vectors.
        resilience:
            Whether to use resilience test vectors.

    Raises:
        FileNotFoundError:
            If the harness is not found.
    """
    if not harness.is_file():
        raise FileNotFoundError(f"harness {str(harness)} not found")

    match harness.suffix:
        case ".py":
            return test_harness_python(harness, compliance, resilience)
        case _:
            raise ValueError(f"No test for '{harness.suffix}' harnesss")
