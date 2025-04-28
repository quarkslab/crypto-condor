"""Module for SLH-DSA."""

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
from crypto_condor.vectors._slhdsa.slhdsa_pb2 import (
    SlhdsaTest,
    SlhdsaVectors,
)
from crypto_condor.vectors.slhdsa import Paramset

# --------------------------- Module --------------------------------------------------

logger = logging.getLogger(__name__)


def __dir__():  # pragma: no cover
    return [
        # Enums
        Wrapper.__name__,
        # Protocols
        Keygen.__name__,
        Sign.__name__,
        Verify.__name__,
        # Test functions
        test_sign.__name__,
        test_verify.__name__,
        test_invariant.__name__,
        # Runners
        test_wrapper.__name__,
        test_wrapper_python.__name__,
        test_lib.__name__,
        # Imported
        Paramset.__name__,
    ]


# --------------------------- Enums ---------------------------------------------------


class Wrapper(strenum.StrEnum):
    """Supported languages for wrappers."""

    PYTHON = "Python"


class Operation(strenum.StrEnum):
    """The types of operations supported, used for selecting test vectors."""

    KEYGEN = "keygen"
    SIGGEN = "siggen"
    SIGVER = "sigver"


# --------------------------- Vectors -------------------------------------------------


def _load_vectors(
    paramset: Paramset, op: Operation, prehash: bool
) -> list[SlhdsaVectors]:
    """Loads vectors for a given parameter set.

    Args:
        paramset:
            The parameter set to load vectors of.
        op:
            The operation to test.
        prehash:
            If True, use HashSLH-DSA vectors.

    Returns:
        A list of vectors.
    """
    vectors_dir = importlib.resources.files("crypto_condor") / "vectors/_slhdsa"
    vectors: list[SlhdsaVectors] = list()

    sources_file = vectors_dir / "slhdsa.json"
    with sources_file.open("r") as file:
        sources = json.load(file)

    files = sources.get(op, None)
    if files is None:
        return vectors

    for filename in files.get(str(paramset)):
        vectors_file = vectors_dir / "pb2" / filename
        _vec = SlhdsaVectors()
        logger.debug("Loading SLH-DSA vectors from %s", str(filename))
        try:
            _vec.ParseFromString(vectors_file.read_bytes())
        except Exception:
            logger.exception("Failed to load SLH-DSA vectors from %s", str(filename))
            continue
        if prehash and _vec.prehash:
            vectors.append(_vec)
        if not prehash and not _vec.prehash:
            vectors.append(_vec)

    return vectors


# --------------------------- Protocols -----------------------------------------------


class Keygen(Protocol):
    """Represents a function that generates SLH-DSA keys."""

    def __call__(self) -> tuple[bytes, bytes]:
        """Generates a SLH-DSA key pair.

        Returns:
            A tuple ``(sk, pk)`` containing the secret key ``sk`` and the public key
            ``pk``.
        """
        ...


class Sign(Protocol):
    """Represents a function that signs with SLH-DSA."""

    def __call__(self, sk: bytes, msg: bytes, ctx: bytes, ph: str) -> bytes:
        """Signs with SLH-DSA.

        Args:
            sk:
                The secret key.
            msg:
                The message to sign.
            ctx:
                The context string. It can be empty.
            ph:
                For the pre-hash variant only, the name of the pre-hash function. For
                the pure variant, it is an empty string and should be ignored.

        Returns:
            The signature.
        """
        ...


class Verify(Protocol):
    """Represents a function that verifies SLH-DSA signatures."""

    def __call__(self, pk: bytes, msg: bytes, sig: bytes, ctx: bytes, ph: str) -> bool:
        """Verifies SLH-DSA signatures.

        Args:
            pk:
                The public key.
            msg:
                The message.
            sig:
                The signature.
            ctx:
                The context string. It can be empty.
            ph:
                For the pre-hash variant only, the name of the pre-hash function. For
                the pure variant, it is an empty string and should be ignored.

        Returns:
            True if the signature is valid, False otherwise.
        """
        ...


# --------------------------- Dataclasses----------------------------------------------


@attrs.define
class SignData:
    """Debug data for :func:`test_sign`.

    Args:
        sk: The secret key.
        msg: The message.
        ctx: The context string.
        ph: The hash function or XOF for HashSLH-DSA.
        sig: The signature.

    Keyword Args:
        ret_sig: The signature returned by the implementation.
    """

    sk: bytes
    msg: bytes
    ctx: bytes
    ph: str
    sig: bytes
    ret_sig: bytes | None = None

    @classmethod
    def from_test(cls, test: SlhdsaTest):
        """Creates a new instance from a test."""
        return cls(test.sk, test.msg, test.ctx, test.ph, test.sig)

    def __str__(self) -> str:
        """Returns a string representation."""
        return f"""sk = {self.sk.hex()}
msg = {self.msg.hex()}
ctx = {self.ctx.hex()}
ph = {self.ph if self.ph else "<none>"}
sig = {self.sig.hex()}
ret_sig = {self.ret_sig.hex() if self.ret_sig is not None else "<none>"}
"""


@attrs.define
class VerData:
    """Debug data for :func:`test_verify`.

    Args:
        pk: The public key.
        msg: The message.
        sig: The signature.
        ctx: The context string.
        ph: The hash function or XOF for HashSLH-DSA.

    Keyword Args:
        ret_valid_sig: Whether the signature is considered valid by the implementation.
    """

    pk: bytes
    msg: bytes
    sig: bytes
    ctx: bytes
    ph: str
    ret_valid_sig: bool | None = None

    @classmethod
    def from_test(cls, test: SlhdsaTest):
        """Creates a new instance from a test."""
        return cls(test.pk, test.msg, test.sig, test.ctx, test.ph)

    def __str__(self) -> str:
        """Returns a string representation."""
        return f"""pk = {self.pk.hex()}
msg = {self.msg.hex()}
sig = {self.sig.hex()}
ctx = {self.ctx.hex()}
ph = {self.ph if self.ph else "<none>"}
ret_valid_sig = {self.ret_valid_sig if self.ret_valid_sig is not None else "<none>"}
"""


@attrs.define
class SignVerData:
    """Debug data for :func:`test_invariant`.

    Args:
        sk: The secret key.
        pk: The public key.
        msg: The message.
        ctx: The context string.
        ph: The pre-hash function, if any.

    Keyword Args:
        ret_sig: The signature returned by the implementation.
        ret_valid_sig: Whether the implementation verified the signature.
    """

    sk: bytes
    pk: bytes
    msg: bytes
    ctx: bytes
    ph: str
    ret_sig: bytes | None = None
    ret_valid_sig: bool | None = None

    @classmethod
    def from_test(cls, test: SlhdsaTest):
        """Creates a new instance from a test."""
        return cls(test.sk, test.pk, test.msg, test.ctx, test.ph)

    def __str__(self) -> str:
        """Returns a string representation."""
        return f"""sk = {self.sk.hex()}
pk = {self.pk.hex()}
msg = {self.msg.hex()}
ctx = {self.ctx.hex()}
ph = {self.ph if self.ph else "<none>"}
ret_sig = {self.ret_sig.hex() if self.ret_sig is not None else "<none>"}
ret_valid_sig = {self.ret_valid_sig if self.ret_valid_sig is not None else "<none>"}
"""


# --------------------------- Test functions ------------------------------------------


def test_sign(
    sign: Sign,
    paramset: Paramset,
    prehash: bool = False,
    deterministic: bool | None = None,
) -> ResultsDict:
    """Tests a function that signs with SLH-DSA.

    Signs messages with the given implementation and then verifies them. The test passes
    if the signatures are valid.

    SLH-DSA has two variants: a hedged, randomized variant, and a deterministic one.
    Testing the hedged version requires an implementation to actually verify the
    signatures, while the deterministic one can be tested by directly comparing the
    signature to the one provided in the test vector. Currently |cc| **only supports
    testing the deterministic variant**.

    Args:
        sign:
            The function to test.
        paramset:
            The parameter set implemented.
        prehash:
            If True, the function implements HashSLH-DSA (message pre-hashing).
        deterministic:
            If True, the function implements deterministic signing. This option is
            ignored for now, as only deterministic signing can be tested.

    Returns:
        A dictionary of results, with one instance of :class:`Results` per test vectors
        file.
    """
    rd = ResultsDict()

    if deterministic is not None and not deterministic:
        logger.error("crypto-condor can only test deterministic signing for now")
        return rd

    all_vectors = _load_vectors(paramset, Operation.SIGGEN, prehash)
    if not all_vectors:
        logger.error(
            "No signature generation test vectors for %s (%s version)",
            str(paramset),
            "prehash" if prehash else "pure",
        )
        return rd

    test: SlhdsaTest
    for vectors in all_vectors:
        res = Results.new("Test SLH-DSA sign", ["paramset", "prehash"])
        rd.add(res, extra_values=[vectors.source])

        for test in track(
            vectors.tests, rf"\[{paramset}]\[{vectors.source}] Test sign"
        ):
            data = SignData.from_test(test)
            info = TestInfo.new_from_test(test, vectors.compliance, data)

            try:
                ret_sig = sign(test.sk, test.msg, test.ctx, test.ph)
            except NotImplementedError:
                logger.error("%s Sign not implemented, test stopped", str(paramset))
                return rd
            except Exception as error:
                logger.debug("Exception caught", exc_info=True)
                info.fail(f"Exception caught: {str(error)}")
                res.add(info)
                continue

            data.ret_sig = ret_sig

            # NOTE: signing test vectors should be all valid, use match/case if not.
            if ret_sig == test.sig:
                info.ok()
            else:
                info.fail("Wrong signature")
            res.add(info)

    return rd


def test_verify(
    verify: Verify, paramset: Paramset, prehash: bool = False
) -> ResultsDict:
    """Tests a function that verifies SLH-DSA signatures.

    Verifies signatures from test vectors using the given function. The test passes if
    valid signature are accepted, while invalid signatures are rejected.

    Args:
        verify:
            The function to test.
        paramset:
            The parameter set implemented.
        prehash:
            If True, the function implements HashSLH-DSA (message pre-hashing).

    Returns:
        A dictionary of results, with one instance of :class:`Results` per test vectors
        file.
    """
    rd = ResultsDict()
    all_vectors = _load_vectors(paramset, Operation.SIGVER, prehash)
    if not all_vectors:
        logger.error(
            "No signature verification test vectors for %s (%s version)",
            str(paramset),
            "prehash" if prehash else "pure",
        )
        return rd

    test: SlhdsaTest
    for vectors in all_vectors:
        res = Results.new("Test SLH-DSA verify", ["paramset", "prehash"])
        rd.add(res, extra_values=[vectors.source])

        for test in track(
            vectors.tests, rf"\[{paramset}]\[{vectors.source}] Test verify"
        ):
            data = VerData.from_test(test)
            info = TestInfo.new_from_test(test, vectors.compliance, data)

            try:
                ret_valid_sig = verify(test.pk, test.msg, test.sig, test.ctx, test.ph)
            except NotImplementedError:
                logger.error("%s Verify not implemented, test stopped", str(paramset))
                return rd
            except Exception as error:
                logger.debug("Exception caught", exc_info=True)
                if test.type == TestType.INVALID:
                    info.ok()
                else:
                    info.fail(f"Exception caught: {str(error)}")
                res.add(info)
                continue

            data.ret_valid_sig = ret_valid_sig

            match (test.type, ret_valid_sig):
                case (TestType.VALID, True):
                    info.ok()
                case (TestType.VALID, False):
                    info.fail("Valid signature rejected")
                case (TestType.INVALID, True):
                    info.fail("Invalid signature accepted")
                case (TestType.INVALID, False):
                    info.ok()
                case _:
                    raise ValueError(
                        f"Invalid test type {test.type} and result {ret_valid_sig}"
                    )
            res.add(info)

    return rd


def test_invariant(
    sign: Sign, verify: Verify, paramset: Paramset, prehash: bool = False
) -> ResultsDict:
    """Tests the sign then verify invariant.

    Signing a message then verifying the signature with the same implementation should
    always work, unless an error occurs while signing. To test this invariant,
    crypto-condor uses some values from test vectors (key pairs, messages, and context
    string) to perform both operations. The test passes if the signatures generated are
    valid.

    Args:
        sign:
            The signing function.
        verify:
            The verification function.
        paramset:
            The parameter set to test.
        prehash:
            If True, the function implements HashSLH-DSA (message pre-hashing).

    Returns:
        A dictionary of results.
    """
    rd = ResultsDict()
    all_vectors = _load_vectors(paramset, Operation.SIGGEN, prehash)
    if not all_vectors:
        logger.error(
            "No signature generation test vectors for %s (%s version)",
            str(paramset),
            "prehash" if prehash else "pure",
        )
        return rd

    test: SlhdsaTest
    for vectors in all_vectors:
        res = Results.new("Test SLH-DSA sign/verify invariant", ["paramset", "prehash"])
        rd.add(res, extra_values=[vectors.source])

        for test in track(
            vectors.tests, rf"\[{paramset}]\[{vectors.source}] Test invariant"
        ):
            data = SignVerData.from_test(test)
            info = TestInfo.new_from_test(test, vectors.compliance, data)

            try:
                ret_sig = sign(test.sk, test.msg, test.ctx, test.ph)
            except NotImplementedError:
                logger.error("%s Sign not implemented, test stopped", str(paramset))
                return rd
            except Exception as error:
                logger.debug("Caught exception", exc_info=True)
                info.fail(f"Exception caught: {str(error)}")
                res.add(info)
                continue

            data.ret_sig = ret_sig

            if len(ret_sig) != paramset.sig_size:
                info.fail(
                    f"Wrong signature size returned (got {len(ret_sig)})",
                    f" expected {paramset.sig_size}",
                )
                res.add(info)
                continue

            try:
                is_valid_sig = verify(test.pk, test.msg, ret_sig, test.ctx, test.ph)
            except NotImplementedError:
                logger.error("%s Verify not implemented, test stopped", str(paramset))
                return rd
            except Exception as error:
                logger.debug("Caught exception", exc_info=True)
                info.fail(f"Exception caught: {str(error)}")
                res.add(info)
                continue

            data.ret_valid_sig = is_valid_sig

            # No test type since the keys are valid and we expect the invariant to hold.
            if is_valid_sig:
                info.ok()
            else:
                info.fail("Signature failed verification")
            res.add(info)

    return rd


# --------------------------- Runners -------------------------------------------------


def test_wrapper_python(
    wrapper: Path, compliance: bool, resilience: bool
) -> ResultsDict:
    """Tests a SLH-DSA Python wrapper.

    Args:
        wrapper:
            A path to the wrapper to test.
        compliance:
            Whether to use compliance test vectors.
        resilience:
            Whether to use resilience test vectors.
    """
    logger.info("Running Python SLH-DSA wrapper: '%s'", str(wrapper.name))
    sys.path.insert(0, str(wrapper.parent.absolute()))
    already_imported = wrapper.stem in sys.modules.keys()
    try:
        slhdsa_wrapper = importlib.import_module(wrapper.stem)
    except ModuleNotFoundError as error:
        logger.error("Can't import wrapper: '%s'", str(error))
        raise
    if already_imported:
        logger.debug("Reloading SLH-DSA wrapper: '%s'", wrapper.stem)
        slhdsa_wrapper = importlib.reload(slhdsa_wrapper)

    rd = ResultsDict()

    for func, _ in inspect.getmembers(slhdsa_wrapper, inspect.isfunction):
        # Initialise variables
        prehash = False
        deterministic = False
        err = False

        # A first match to parse the paramset and optional suffixes.
        match func.split("_"):
            case [
                "CC",
                "SLHDSA",
                pset_hash,
                pset_strength,
                ("keygen" | "sign" | "verify" | "invariant"),
                ("pure" | "prehash") as variant,
                *optional,
            ]:
                try:
                    paramset = Paramset.from_name(pset_hash, pset_strength)
                except ValueError:
                    logger.error(
                        "Invalid parameter set %s_%s in function %s",
                        pset_hash,
                        pset_strength,
                        func,
                    )
                    err = True

                if variant == "prehash":
                    prehash = True

                # We use a catch-all for the options to manage both the case of no
                # options given or one-or-more options given.
                # That said, we expect at most one option, so log an error if there are
                # more than one,
                if len(optional) > 1:
                    logger.error(
                        "Too many options at the end of function name %s", func
                    )
                    err = True
                else:
                    # Iterating through a list works even if its empty, skipping a
                    # length check to determine if it's safe to access or pop the item.
                    for option in optional:
                        if option == "det":
                            deterministic = True
                        else:
                            logger.error(
                                "Invalid option %s in function %s", option, func
                            )
                            err = True
            case _:
                logger.error("Invalid CC_SLHDSA function %s", func)
                continue

        if err:
            logger.error("Failed to parse function name %s", func)
            continue

        wrapper_func = getattr(slhdsa_wrapper, func)

        # Since we determined the value of the parameters, we can catch all options
        # after the operation and just rely on our parsed parameters from above, except
        # for invariant, since we need to determine the names of the functions to test.
        # Technically, the `variant` is already set, but let's avoid obscure errors of
        # unbound variables and parse it again.
        match func.split("_"):
            case [
                "CC",
                "SLHDSA",
                pset_hash,
                pset_strength,
                "keygen",
                ("pure" | "prehash"),
            ]:
                pass
            case ["CC", "SLHDSA", pset_hash, pset_strength, "sign", *_]:
                rd |= test_sign(wrapper_func, paramset, prehash, deterministic)
            case ["CC", "SLHDSA", pset_hash, pset_strength, "verify", *_]:
                rd |= test_verify(wrapper_func, paramset, prehash)
            case [
                "CC",
                "SLHDSA",
                pset_hash,
                pset_strength,
                "invariant",
                ("pure" | "prehash") as variant,
            ]:
                # Find a suitable signing function, using the hedged variant first.
                sign_name = f"CC_SLHDSA_{pset_hash}_{pset_strength}_sign_{variant}"
                sign_func = getattr(slhdsa_wrapper, sign_name, None)
                if sign_func is None:
                    det_sign_name = (
                        f"CC_SLHDSA_{pset_hash}_{pset_strength}_sign_{variant}_det"
                    )
                    sign_func = getattr(slhdsa_wrapper, det_sign_name, None)
                    if sign_func is None:
                        logger.error(
                            "Could not find a suitable signing function for %s", func
                        )
                        logger.info("Hint: expected %s or %s", sign_name, det_sign_name)
                        continue
                # No deterministic version of verifying.
                ver_name = f"CC_SLHDSA_{pset_hash}_{pset_strength}_verify_{variant}"
                ver_func = getattr(slhdsa_wrapper, ver_name, None)
                if ver_func is None:
                    logger.error(
                        "Could not find a suitable verifyin function for %s", func
                    )
                    logger.info("Hint: expected %s", ver_name)
                    continue
                rd |= test_invariant(sign_func, ver_func, paramset, prehash)

    return rd


def test_wrapper(wrapper: Path, compliance: bool, resilience: bool) -> ResultsDict:
    """Tests a SLH-DSA wrapper.

    Args:
        wrapper:
            The wrapper to test.
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


# --------------------------- Harness -------------------------------------------------


def _test_harness_sign(
    ffi: cffi.FFI,
    lib,
    func: str,
    paramset: Paramset,
    prehash: bool,
    deterministic: bool,
) -> ResultsDict:
    logger.info("Testing harness function %s", func)

    ffi.cdef(
        f"""
        int {func}(uint8_t *sig, size_t sig_size,
            const uint8_t *msg, size_t msg_size,
            const uint8_t *ctx, size_t ctx_size,
            const uint8_t *sk, size_t sk_size,
            const char *ph, size_t ph_size);
    """,
        override=True,
    )

    lib_sign = getattr(lib, func)

    def sign(sk: bytes, msg: bytes, ctx: bytes, ph: str) -> bytes:
        c_sig = ffi.new(f"uint8_t[{paramset.sig_size}]")
        c_sk = ffi.new("uint8_t[]", sk)
        c_msg = ffi.new("uint8_t[]", msg)
        c_ctx = ffi.new("uint8_t[]", ctx)
        c_ph = ffi.new("char[]", ph.encode("utf-8"))

        rc = lib_sign(
            c_sig,
            paramset.sig_size,
            c_msg,
            len(msg),
            c_ctx,
            len(ctx),
            c_sk,
            len(sk),
            c_ph,
            len(ph),
        )
        if rc == 1:
            return bytes(c_sig)
        else:
            raise ValueError(f"{func} failed with status {rc}")

    return test_sign(sign, paramset, prehash=prehash, deterministic=deterministic)


def _test_harness_verify(
    ffi: cffi.FFI, lib, func: str, paramset: Paramset, prehash: bool
) -> ResultsDict:
    logger.info("Testing harness function %s", func)

    ffi.cdef(
        f"""
    int {func}(const uint8_t *sig, size_t sig_size,
            const uint8_t *msg, size_t msg_size,
            const uint8_t *ctx, size_t ctx_size,
            const uint8_t *pk, size_t pk_size,
            const char *ph, size_t ph_size);
    """,
        override=True,
    )

    lib_verify = getattr(lib, func)

    def verify(pk: bytes, msg: bytes, sig: bytes, ctx: bytes, ph: str) -> bool:
        c_pk = ffi.new("uint8_t[]", pk)
        c_msg = ffi.new("uint8_t[]", msg)
        c_sig = ffi.new("uint8_t[]", sig)
        c_ctx = ffi.new("uint8_t[]", ctx)
        c_ph = ffi.new("char[]", ph.encode("utf-8"))

        rc = lib_verify(
            c_sig,
            len(sig),
            c_msg,
            len(msg),
            c_ctx,
            len(ctx),
            c_pk,
            len(pk),
            c_ph,
            len(ph),
        )
        if rc == 1:
            return True
        elif rc == 0:
            return False
        else:
            raise ValueError(f"{func} failed with status {rc}")

    return test_verify(verify, paramset, prehash=prehash)


def _test_harness_invariant(
    ffi: cffi.FFI, lib, sign_func: str, ver_func: str, paramset: Paramset, prehash: bool
) -> ResultsDict:
    logger.info("Testing harness functions %s and %s", sign_func, ver_func)

    ffi.cdef(
        f"""
        int {sign_func}(uint8_t *sig, size_t sig_size,
            const uint8_t *msg, size_t msg_size,
            const uint8_t *ctx, size_t ctx_size,
            const uint8_t *sk, size_t sk_size,
            const char *ph, size_t ph_size);

        int {ver_func}(const uint8_t *sig, size_t sig_size,
            const uint8_t *msg, size_t msg_size,
            const uint8_t *ctx, size_t ctx_size,
            const uint8_t *pk, size_t pk_size,
            const char *ph, size_t ph_size);
    """,
        override=True,
    )

    lib_sign = getattr(lib, sign_func)
    lib_verify = getattr(lib, ver_func)

    def sign(sk: bytes, msg: bytes, ctx: bytes, ph: str) -> bytes:
        c_sig = ffi.new(f"uint8_t[{paramset.sig_size}]")
        c_sk = ffi.new("uint8_t[]", sk)
        c_msg = ffi.new("uint8_t[]", msg)
        c_ctx = ffi.new("uint8_t[]", ctx)
        c_ph = ffi.new("char[]", ph.encode("utf-8"))

        rc = lib_sign(
            c_sig,
            paramset.sig_size,
            c_msg,
            len(msg),
            c_ctx,
            len(ctx),
            c_sk,
            len(sk),
            c_ph,
            len(ph),
        )
        if rc == 1:
            return bytes(c_sig)
        else:
            raise ValueError(f"{sign_func} failed with status {rc}")

    def verify(pk: bytes, msg: bytes, sig: bytes, ctx: bytes, ph: str) -> bool:
        c_pk = ffi.new("uint8_t[]", pk)
        c_msg = ffi.new("uint8_t[]", msg)
        c_sig = ffi.new("uint8_t[]", sig)
        c_ctx = ffi.new("uint8_t[]", ctx)
        c_ph = ffi.new("char[]", ph.encode("utf-8"))

        rc = lib_verify(
            c_sig,
            len(sig),
            c_msg,
            len(msg),
            c_ctx,
            len(ctx),
            c_pk,
            len(pk),
            c_ph,
            len(ph),
        )
        if rc == 1:
            return True
        elif rc == 0:
            return False
        else:
            raise ValueError(f"{ver_func} failed with status {rc}")

    return test_invariant(sign, verify, paramset, prehash=prehash)


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
            A list of CC_Kyber functions to test.
        compliance:
            Whether to use compliance test vectors.
        resilience:
            Whether to use resilience test vectors.
    """
    logger.info("Found harness functions: %s", ", ".join(functions))

    rd = ResultsDict()

    for func in functions:
        # Initialise variables
        prehash = False
        deterministic = False
        err = False

        # A first match to parse the paramset and optional suffixes.
        match func.split("_"):
            case [
                "CC",
                "SLHDSA",
                pset_hash,
                pset_strength,
                ("keygen" | "sign" | "verify" | "invariant"),
                ("pure" | "prehash") as variant,
                *optional,
            ]:
                try:
                    paramset = Paramset.from_name(pset_hash, pset_strength)
                except ValueError:
                    logger.error(
                        "Invalid parameter set %s_%s in function %s",
                        pset_hash,
                        pset_strength,
                        func,
                    )
                    err = True

                if variant == "prehash":
                    prehash = True

                # We use a catch-all for the options to manage both the case of no
                # options given or one-or-more options given.
                # That said, we expect at most one option, so log an error if there are
                # more than one,
                if len(optional) > 1:
                    logger.error(
                        "Too many options at the end of function name %s", func
                    )
                    err = True
                else:
                    # Iterating through a list works even if its empty, skipping a
                    # length check to determine if it's safe to access or pop the item.
                    for option in optional:
                        if option == "det":
                            deterministic = True
                        else:
                            logger.error(
                                "Invalid option %s in function %s", option, func
                            )
                            err = True
            case _:
                logger.error("Invalid CC_SLHDSA function %s", func)
                continue

        if err:
            logger.error("Failed to parse function name %s", func)
            continue

        # Since we determined the value of the parameters, we can catch all options
        # after the operation and just rely on our parsed parameters from above, except
        # for invariant, since we need to determine the names of the functions to test.
        # Technically, the `variant` is already set, but let's avoid obscure errors of
        # unbound variables and parse it again.
        match func.split("_"):
            case [
                "CC",
                "SLHDSA",
                pset_hash,
                pset_strength,
                "keygen",
                ("pure" | "prehash"),
            ]:
                pass
            case [
                "CC",
                "SLHDSA",
                pset_hash,
                pset_strength,
                "sign",
                ("pure" | "prehash"),
                *_,
            ]:
                rd |= _test_harness_sign(
                    ffi, lib, func, paramset, prehash, deterministic
                )
            case [
                "CC",
                "SLHDSA",
                pset_hash,
                pset_strength,
                "verify",
                ("pure" | "prehash"),
            ]:
                rd |= _test_harness_verify(ffi, lib, func, paramset, prehash)
            case [
                "CC",
                "SLHDSA",
                pset_hash,
                pset_strength,
                "invariant",
                ("pure" | "prehash"),
            ]:
                # Find a suitable signing function, using the hedged variant first.
                sign_name = f"CC_SLHDSA_{pset_hash}_{pset_strength}_sign_{variant}"
                if sign_name not in functions:
                    det_sign_name = (
                        f"CC_SLHDSA_{pset_hash}_{pset_strength}_sign_{variant}_det"
                    )
                    if det_sign_name not in functions:
                        logger.error(
                            "Could not find a suitable signing function for %s", func
                        )
                        logger.info("Hint: expected %s or %s", sign_name, det_sign_name)
                        continue
                    else:
                        sign_name = det_sign_name
                # No deterministic version of verifying.
                ver_name = f"CC_SLHDSA_{pset_hash}_{pset_strength}_verify_{variant}"
                if ver_name not in functions:
                    logger.error(
                        "Could not find a suitable verifying function for %s", func
                    )
                    logger.info("Hint: expected %s", ver_name)
                    continue

                rd |= _test_harness_invariant(
                    ffi, lib, sign_name, ver_name, paramset, prehash
                )

    return rd
