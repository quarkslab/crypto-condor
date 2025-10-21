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

# -------------------------------------------------------------------------------------
# Module
# -------------------------------------------------------------------------------------

logger = logging.getLogger(__name__)


def __dir__():  # pragma: no cover
    return [
        # Enums
        Wrapper.__name__,
        # Protocols
        Exchange.__name__,
        Keygen.__name__,
        # Test functions
        test_exchange.__name__,
        test_keygen.__name__,
        # Runners
        test_harness.__name__,
        test_harness_python.__name__,
    ]


# -------------------------------------------------------------------------------------
# Enums
# -------------------------------------------------------------------------------------


class Wrapper(strenum.StrEnum):
    """Supported languages for wrappers."""

    PYTHON = "Python"


# -------------------------------------------------------------------------------------
# Test vectors
# -------------------------------------------------------------------------------------


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


# -------------------------------------------------------------------------------------
# Protocols
# -------------------------------------------------------------------------------------


class Exchange(Protocol):
    """Represents a function that performs the X25519 key exchange."""

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


class Keygen(Protocol):
    """Represents a function that generates X25519 key pairs."""

    def __call__(self) -> tuple[bytes, bytes | None]:  # pragma: no cover
        """Generates a X25519 key pair.

        Returns:
            A tuple containing (secret key, public key) or (secret key, None).
        """
        ...


# -------------------------------------------------------------------------------------
# Dataclasses
# -------------------------------------------------------------------------------------


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


@attrs.define
class KeygenData:
    """Debug data for `test_keygen`."""

    sk: bytes
    pk: bytes | None

    def __str__(self):
        """Returns a string representation."""
        return f"""sk = {self.sk.hex()}
pk = {self.pk.hex() if self.pk is not None else "<none>"}
"""


# -------------------------------------------------------------------------------------
# Internal functions
# -------------------------------------------------------------------------------------


def _is_clamped(key: bytes) -> bool:
    """Returns True if the key is clamped.

    X25519 keys are in little endian. Checks if the last three bits are not set and if
    the first byte starts with 0b01.
    """
    return (key[0] & 0x07 == 0) and (key[-1] & 0xC0 == 0x40)


# -------------------------------------------------------------------------------------
# Test functions
# -------------------------------------------------------------------------------------


def test_exchange(
    exchange: Exchange, compliance: bool, resilience: bool
) -> ResultsDict:
    """Tests a function implementing the X25519 key exchange.

    Calls the ``exchange`` function to perform a X25519 key exchange.

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


def test_keygen(keygen: Keygen, nbytes: int = 10_000_000) -> ResultsDict:
    """Tests a function that generates X25519 key pairs.

    This test checks both the correct generation of key pairs, as well as the quality of
    the randomness of the private keys.

    It calls ``keygen`` to generate enough keys to fill a buffer of length ``nbytes``.
    If the public key is included, the test checks that the public key corresponds to
    the private key.

    The private keys are concatenated and tested with
    :mod:`~crypto_condor.primitives.TestU01`. X25519 keys can be clamped (see the
    :doc:`method guide </method/x25519>`) but some implementations may store the raw key
    and clamp it when performing the key exchange. This test first calls ``keygen`` to
    generate some sample keys and check if they are clamped. If all of them are, the
    first and last bytes of each key are removed from the input to TestU01. Also, the
    test checks that all other keys are correctly clamped, marking the individual test
    as failed if not.

    Args:
        keygen:
            The key generation function to test.
        nbytes:
            The number of bytes to generate. TestU01 requires at least 100 000 bytes.

    Returns:
        A :class:`ResultsDict` with two :class:`Results`: one containing the results of
        generating all the keys and one containing the results from TestU01.

    Raises:
        ValueError:
            If ``nbytes`` is less than 100 000.
    """
    if nbytes < 100_000:
        raise ValueError(f"TestU01 requires at least 100 000 bytes, got {nbytes}")

    from math import ceil
    from crypto_condor.primitives import TestU01

    results = ResultsDict()

    try:
        testkeys = [keygen() for _ in range(10)]
    except Exception:
        logger.exception("Failed to run X25519 keygen, returning empty ResultsDict")
        return results
    clamped = all([_is_clamped(key) for key, _ in testkeys])

    nkeys = ceil(nbytes / 30) if clamped else ceil(nbytes / 32)
    keys = bytes()

    res = Results.new("Tests X25519 key pair generation", ["nbytes"])
    results.add(res)

    for i in track(range(1, nkeys + 1), "Testing keys"):
        info = TestInfo.new(i, TestType.VALID)

        try:
            out = keygen()
        except Exception as error:
            info.fail("Failed to run X25519 keygen")
            res.add(info)
            continue

        match out:
            case [bytes() as sk, bytes() as pk]:
                # Nothing to do, match does the assignment for us.
                pass
            case [bytes() as sk, None]:
                pk = None
            case [_a, _b]:
                info.fail(
                    f"Expected (bytes, bytes | None), got ({type(_a)}, {type(_b)})"
                )
                res.add(info)
                continue
            case _:
                info.fail(f"Expected 2 values, got {len(out)}")
                res.add(info)
                continue

        info.data = KeygenData(sk, pk)

        if len(sk) != 32:
            info.fail("Wrong secret key size")
            res.add(info)
            continue

        tk = sk
        if clamped:
            # If the first sample keys were clamped, all other keys should be too.
            if not _is_clamped(sk):
                info.fail("Key is not clamped (other keys were)")
                res.add(info)
                continue
            # If keys are clamped, remove first and last bytes from TestU01 input.
            tk = tk[1:-1]
        keys += tk

        if pk is None:
            info.ok()
        else:
            key = X25519PrivateKey.from_private_bytes(sk)
            if key.public_key().public_bytes_raw() == pk:
                info.ok()
            else:
                info.fail("Wrong public key")
        res.add(info)

    # Test the keygen output with TestU01.
    results |= TestU01.test_raw(keys)

    return results


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

    for name, func in inspect.getmembers(module_harness, inspect.isfunction):
        match name.split("_"):
            case ["CC", "x25519", "exchange"]:
                rd |= test_exchange(func, compliance, resilience)
            case ["CC", "x25519", "keygen"]:
                rd |= test_keygen(func)
            case ["CC", "x25519", "keygen", _nbytes]:
                try:
                    nbytes = int(_nbytes)
                except ValueError:
                    logger.error("Failed to parse %s as int", _nbytes)
                    continue
                rd |= test_keygen(func, nbytes)
            case ["CC", "x25519", *_]:
                logger.error("Invalid function CC_x25519 %s", name)
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
