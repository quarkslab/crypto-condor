"""The ChaCha20 module."""

import ctypes
import importlib
import logging
import sys
from pathlib import Path
from typing import Literal, Protocol, overload

import attrs
import strenum
from Crypto.Cipher import ChaCha20, ChaCha20_Poly1305
from rich.progress import track

from crypto_condor.primitives.common import (
    CiphertextAndTag,
    DebugInfo,
    PlaintextAndBool,
    Results,
    ResultsDict,
    TestType,
)
from crypto_condor.vectors.ChaCha20 import ChaCha20Vectors, Mode

logger = logging.getLogger(__name__)


def __dir__():  # pragma: no cover
    return [
        # Enums
        Operation.__name__,
        Wrapper.__name__,
        # Protocols
        Encrypt.__name__,
        Decrypt.__name__,
        # Dataclasses
        # Test functions
        test.__name__,
        verify_file.__name__,
        run_wrapper.__name__,
        # Imported
        Mode.__name__,
    ]


# --------------------------- Enums ---------------------------------------------------


class Operation(strenum.StrEnum):
    """Supported operations."""

    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"


class Wrapper(strenum.StrEnum):
    """Supported wrapper languages."""

    PYTHON = "Python"


# --------------------------- Protocols -----------------------------------------------


class Encrypt(Protocol):
    """Represents a function that encrypts with ChaCha20.

    Encryption functions must behave like one of the :func:`__call__` overloads below to
    be tested with this module. The first corresponds to ChaCha20, the second to
    ChaCha20-Poly1305.
    """

    @overload
    def __call__(
        self, key: bytes, plaintext: bytes, nonce: bytes, *, init_counter: int = 0
    ) -> bytes: ...

    @overload
    def __call__(
        self, key: bytes, plaintext: bytes, nonce: bytes, *, aad: bytes | None
    ) -> CiphertextAndTag: ...

    def __call__(
        self,
        key: bytes,
        plaintext: bytes,
        nonce: bytes,
        *,
        init_counter: int = 0,
        aad: bytes | None = None,
    ) -> bytes | CiphertextAndTag:
        """Encrypts with ChaCha20(-Poly1305).

        Args:
            key: The symmetric key.
            plaintext: The message to encrypt.
            nonce: The nonce to use for this message.

        Keyword Args:
            init_counter: (ChaCha20 only) A position to seek in the keystream before
                encrypting, in bytes.
            aad: (ChaCha20-Poly1305 only) The associated data, can be empty or None.

        Returns:
            (ChaCha20) The ciphertext.

            (ChaCha20-Poly1305) A (ciphertext, MAC) tuple.
        """
        ...  # pragma: no cover (nothing to cover)


class Decrypt(Protocol):
    """Represents a function that decrypts with ChaCha20.

    Decryption functions must behave like one of the :func:`__call__` overloads below to
    be tested with this module. The first corresponds to ChaCha20, the second to
    ChaCha20-Poly1305.

    """

    @overload
    def __call__(
        self, key: bytes, ciphertext: bytes, nonce: bytes, *, init_counter: int = 0
    ) -> bytes: ...

    @overload
    def __call__(
        self,
        key: bytes,
        ciphertext: bytes,
        nonce: bytes,
        *,
        mac: bytes,
        aad: bytes | None,
    ) -> PlaintextAndBool: ...

    def __call__(
        self,
        key: bytes,
        ciphertext: bytes,
        nonce: bytes,
        *,
        init_counter: int = 0,
        mac: bytes = b"",
        aad: bytes | None = None,
    ) -> bytes | PlaintextAndBool:
        """Decrypts with ChaCha20(-Poly1305).

        Args:
            key: The symmetric key.
            ciphertext: The message to decrypt.
            nonce: The nonce to use for this message.

        Keyword Args:
            init_counter: (ChaCha20 only) A position to seek in the keystream before
                encrypting, in bytes.
            mac: (ChaCha20-Poly1305 only) The MAC tag to use for authenticating the
                ciphertext.
            aad: (ChaCha20-Poly1305 only) The associated data, can be empty or None.

        Returns:
            (ChaCha20) The plaintext.

            (ChaCha20-Poly1305) If the MAC is valid, a (plaintext, True) tuple.
            Otherwise the plaintext should not be released, so return a (None, False)
            tuple.
        """
        ...  # pragma: no cover (nothing to cover)


# ---------------------- Dataclasses---------------------------------------------


@attrs.define
class ChaCha20Data:
    """ChaCha20 debug test data.

    Args:
        info: General info on the test, see :class:`DebugInfo`.
        operation: The operation performed.
        key: The symmetric key used. Only expected to be None when a line could not be
            read correctly by :func:`verify_file`.
        message: The message to encrypt or decrypt. Only expected to be None when a line
            could not be read correctly by :func:`verify_file`.
        expected: The expected ciphertext or plaintext depending on the operation
            performed. Only expected to be None when a line could not be read correctly
            by :func:`verify_file`.
        result: The actual ciphertext or plaintext obtained, None if the implementation
            failed to return.
        nonce: The nonce used for the operation.
        init_counter: (ChaCha20 only) The initial value of the counter, used for seeking
            a position in the keystream before the operation.
        aad: (ChaCha20-Poly1305 only) The associated data, can be empty or None.
        expected_mac: (ChaCha20-Poly1305 only) When encrypting, it is the MAC tag the
            implementation is expected to return. When decrypting, it is the MAC tag
            used to authenticate the ciphertext.
        mac: (ChaCha20-Poly1305 only) The MAC returned by the implementation when
            encrypting.
        valid_mac: (ChaCha20-Poly1305 only) Whether the implementation considers the MAC
            valid when decrypting.
    """

    info: DebugInfo
    operation: Operation
    key: bytes | None
    message: bytes | None
    expected: bytes | None
    result: bytes | None = None
    nonce: bytes | None = None
    init_counter: int | None = None
    aad: bytes | None = None
    expected_mac: bytes | None = None
    mac: bytes | None = None
    valid_mac: bool | None = None

    def __str__(self):
        """Returns a string representation of the present fields."""
        s = str(self.info)

        s += f"Operation: {self.operation}\n"
        s = f"key = {self.key.hex()}\n"
        s += f"message = {self.message.hex() if self.message else '<empty>'}\n"
        s += f"expected = {self.expected.hex() if self.expected else '<empty>'}\n"

        # If no tag verification or valid MAC, try to print the result, otherwise if the
        # MAC is invalid don't release the plaintext even if it was returned.
        if self.valid_mac is None or self.valid_mac:
            s += f"result = {self.result.hex() if self.result else '<empty>'}\n"
        else:
            s += "result = <decryption error>\n"

        if self.nonce is not None:
            s += f"nonce = {self.nonce.hex() if self.nonce else '<empty>'}\n"
        if self.init_counter is not None:
            s += f"init_counter = {self.init_counter}\n"
        if self.aad is not None:
            s += f"aad = {self.aad.hex() if self.aad else '<empty>'}\n"
        if self.mac is not None:
            s += f"tag = {self.mac.hex() if self.mac else '<empty>'}\n"
        if self.expected_mac is not None:
            et = f"{self.expected_mac.hex() if self.expected_mac else '<empty>'}"
            s += f"expected tag = {et}"
        if self.valid_mac is not None:
            s += f"MAC is valid = {'TRUE' if self.valid_mac else 'FALSE'}"

        return s


# ----------------------------- ChaCha20 functions -------------------------------------


# classic
@overload
def _encrypt(
    mode: Literal[Mode.CHACHA20],
    key: bytes,
    plaintext: bytes,
    nonce: bytes,
    *,
    init_counter: int = 0,
) -> bytes: ...


# Poly1305
@overload
def _encrypt(
    mode: Literal[Mode.CHACHA20_POLY1305],
    key: bytes,
    plaintext: bytes,
    nonce: bytes,
    *,
    aad: bytes | None = None,
) -> CiphertextAndTag: ...


def _encrypt(
    mode: Mode,
    key: bytes,
    plaintext: bytes,
    nonce: bytes,
    *,
    init_counter: int = 0,
    aad: bytes | None = None,
) -> bytes | CiphertextAndTag:
    cipher: ChaCha20.ChaCha20Cipher | ChaCha20_Poly1305.ChaCha20Poly1305Cipher
    if mode == Mode.CHACHA20_POLY1305:
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        if aad:
            cipher.update(aad)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return (ciphertext, tag)
    else:
        cipher = ChaCha20.new(key=key, nonce=nonce)
        if init_counter:
            cipher.seek(64 * init_counter)
        ciphertext = cipher.encrypt(plaintext)
        return ciphertext


# classic
@overload
def _decrypt(
    mode: Literal[Mode.CHACHA20],
    key: bytes,
    ciphertext: bytes,
    nonce: bytes,
    *,
    init_counter: int = 0,
) -> bytes: ...


# Poly1305
@overload
def _decrypt(
    mode: Mode,
    key: bytes,
    ciphertext: bytes,
    nonce: bytes,
    *,
    mac: bytes,
    aad: bytes | None,
) -> PlaintextAndBool: ...


def _decrypt(
    mode: Mode,
    key: bytes,
    ciphertext: bytes,
    nonce: bytes,
    *,
    init_counter: int = 0,
    mac: bytes | None = None,
    aad: bytes | None = None,
) -> bytes | PlaintextAndBool:
    cipher: ChaCha20.ChaCha20Cipher | ChaCha20_Poly1305.ChaCha20Poly1305Cipher
    if mode == Mode.CHACHA20_POLY1305:
        if mac is None:
            raise ValueError("Authenticated modes require the MAC tag.")

        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        if aad:
            cipher.update(aad)
        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, mac)

            return (plaintext, True)
        except ValueError:
            return (None, False)
    else:
        cipher = ChaCha20.new(key=key, nonce=nonce)
        if init_counter:
            cipher.seek(64 * init_counter)
        plaintext = cipher.decrypt(ciphertext)
        return plaintext


# --------------------------- Test functions ------------------------------------------


def _test_wycheproof_encrypt(encrypt: Encrypt, mode: Mode) -> Results:
    """Tests a mode of operation with Wycheproof test vectors.

    Args:
        encrypt: The function to test.
        mode: The mode of operation.
    """
    results = Results(
        "ChaCha20",
        "test_encrypt",
        "Tests encryption with Wycheproof vectors",
        {"mode": mode},
    )

    vectors = ChaCha20Vectors.load(mode)

    for group in track(
        vectors.wycheproof["testGroups"], f"[Wycheproof] Encrypt {str(mode)} vectors"
    ):
        for test in group["tests"]:
            key = bytes.fromhex(test["key"])
            nonce = bytes.fromhex(test["iv"])
            plaintext = bytes.fromhex(test["msg"])
            ciphertext = bytes.fromhex(test["ct"])
            if mode == Mode.CHACHA20_POLY1305:
                mac = bytes.fromhex(test["tag"]) if test["tag"] else None
                aad = bytes.fromhex(test["aad"]) if test["aad"] else None
                init_counter = None
            else:
                mac = None
                aad = None
                init_counter = int(test["init_counter"])

            test_type = TestType(test["result"])
            if test["flags"]:
                flags = test["flags"]
            elif plaintext:
                flags = ["Resilience"]
            else:
                flags = ["Resilience/EmptyPlaintext"]
            info = DebugInfo(
                test["tcId"], test_type, flags, comment=test.get("comment", None)
            )
            data = ChaCha20Data(
                info,
                Operation.ENCRYPT,
                key,
                plaintext,
                ciphertext,
                nonce=nonce,
                aad=aad,
                expected_mac=mac,
                init_counter=init_counter,
            )
            try:
                if mode == Mode.CHACHA20_POLY1305:
                    ct, mt = encrypt(key, plaintext, nonce, aad=aad)
                    res = (ct == ciphertext) and (mt == mac)
                else:
                    init_counter = int(test.get("init_counter", "0"))
                    ct = encrypt(key, plaintext, nonce, init_counter=init_counter)
                    mt = None
                    res = ct == ciphertext
            except ValueError as error:
                if test_type == TestType.INVALID:
                    info.result = True
                else:
                    info.error_msg = f"Encryption error: {str(error)}"
                    logger.debug("Encryption error", exc_info=True)
                results.add(data)
                continue

            data.result = ct
            data.mac = mt
            match (test_type, res):
                case (TestType.VALID, True) | (TestType.INVALID, False):
                    info.result = True
                case (TestType.VALID, False) | (TestType.INVALID, True):
                    if test_type == TestType.INVALID:
                        info.error_msg = "Invalid ciphertext and MAC produced"
                    elif mac is not None:
                        if ct != ciphertext and mt != mac:
                            info.error_msg = "Wrong ciphertext and MAC"
                        elif ct != ciphertext:
                            info.error_msg = "Wrong ciphertext"
                        else:
                            info.error_msg = "Wrong MAC"
                    else:
                        info.error_msg = "Wrong ciphertext"
                case (TestType.ACCEPTABLE, (True | False)):
                    info.result = res
            results.add(data)

    return results


def _test_wycheproof_decrypt(decrypt: Decrypt, mode: Mode) -> Results:
    """Tests a mode of operation with Wycheproof test vectors.

    Args:
        decrypt: The function to test.
        mode: The mode of operation.
    """
    results = Results(
        "ChaCha20",
        "test_decrypt",
        "Tests decryption with Wycheproof vectors",
        {"mode": mode},
    )

    vectors = ChaCha20Vectors.load(mode)

    for group in track(
        vectors.wycheproof["testGroups"], f"[Wycheproof] Decrypt {str(mode)} vectors"
    ):
        for test in group["tests"]:
            key = bytes.fromhex(test["key"])
            nonce = bytes.fromhex(test["iv"])
            plaintext = bytes.fromhex(test["msg"])
            ciphertext = bytes.fromhex(test["ct"])
            mac = None
            aad = None
            if mode == Mode.CHACHA20_POLY1305 and test["aad"]:
                aad = bytes.fromhex(test["aad"])

            test_type = TestType(test["result"])
            if test["flags"]:
                flags = test["flags"]
            elif plaintext:
                flags = ["Resilience"]
            else:
                flags = ["Resilience/EmptyCiphertext"]
            info = DebugInfo(
                test["tcId"], test_type, flags, comment=test.get("comment", None)
            )
            data = ChaCha20Data(
                info,
                Operation.DECRYPT,
                key,
                ciphertext,
                plaintext,
                nonce=nonce,
                aad=aad,
            )

            try:
                if mode == Mode.CHACHA20_POLY1305:
                    mac = bytes.fromhex(test.get("tag", ""))
                    data.expected_mac = mac
                    pt, status = decrypt(key, ciphertext, nonce, mac=mac, aad=aad)
                    res = status and (pt == plaintext)
                    data.result = pt
                    data.valid_mac = status
                else:
                    init_counter = int(test.get("init_counter", "0"))
                    data.init_counter = init_counter
                    pt = decrypt(key, ciphertext, nonce, init_counter=init_counter)
                    res = pt == plaintext
                    data.result = pt
            except (AssertionError, ValueError) as error:
                if test_type == TestType.INVALID:
                    info.result = True
                else:
                    info.error_msg = f"Decryption error: {str(error)}"
                    logger.debug("Decryption error", exc_info=True)
                results.add(data)
                continue

            match (test_type, res):
                case (TestType.VALID, True) | (TestType.INVALID, False):
                    info.result = True
                case (TestType.VALID, False) | (TestType.INVALID, True):
                    if test_type == TestType.INVALID:
                        info.error_msg = "Invalid plaintext/MAC accepted"
                    elif mac is not None and not status:
                        info.error_msg = "MAC verification failed"
                    else:
                        info.error_msg = "Wrong plaintext"
                case (TestType.ACCEPTABLE, (True | False)):
                    info.result = res
            results.add(data)

    return results


def test(
    encrypt: Encrypt | None,
    decrypt: Decrypt | None,
    mode: Mode,
    *,
    resilience: bool = True,
) -> ResultsDict:
    """Tests an implementation of ChaCha20(-Poly1305) encryption and decryption.

    It runs test vectors on the given functions. These functions must conform to the
    :protocol:`Encrypt` and :protocol:`Decrypt` protocols.

    Args:
        encrypt: The encryption function to test. Using None skips this test.
        decrypt: The decryption function to test. Using None skips this test.
        mode: The mode of operation to test.

    Keyword Args:
        resilience: If True, runs Wycheproof test vectors.

    Returns:
        A dictionary of results.

        If resilience is True, Wycheproof vectors are used. The results are indexed by
        ``ChaCha20/test_wycheproof_[encrypt/decrypt]/[mode]``.

    Example:
        Let's test PyCryptodome's implementation of ChaCha20.

        We start by importing the ChaCha20 modules of crypto-condor and PyCryptodome.

        >>> from crypto_condor.primitives import ChaCha20
        >>> from Crypto.Cipher import ChaCha20 as pyChaCha20

        We need to wrap PyCryptodome's to match the signature of :protocol:`Encrypt` and
        :protocol:`Decrypt`. In both cases we want to match the first overload, as it is
        the one that corresponds to ChaCha20.

        >>> def my_enc(
        ...     key: bytes,
        ...     plaintext: bytes,
        ...     nonce: bytes,
        ...     *,
        ...     init_counter: int = 0
        ... ) -> bytes:
        ...     cipher = pyChaCha20.new(key=key, nonce=nonce)
        ...     if init_counter > 0:
        ...         cipher.seek(64 * init_counter)
        ...     return cipher.encrypt(plaintext)
        >>> def my_dec(
        ...     key: bytes,
        ...     ciphertext: bytes,
        ...     nonce: bytes,
        ...     *,
        ...     init_counter: int = 0
        ... ) -> bytes:
        ...     cipher = pyChaCha20.new(key=key, nonce=nonce)
        ...     if init_counter > 0:
        ...         cipher.seek(64 * init_counter)
        ...     return cipher.decrypt(ciphertext)

        And we test the functions we defined.

        >>> mode = ChaCha20.Mode.CHACHA20
        >>> results_dict = ChaCha20.test(my_enc, my_dec, mode)
        [Wycheproof] ...
        >>> assert results_dict.check()
    """
    rd = ResultsDict()
    if not resilience:  # pragma: no cover (not interesting)
        return rd

    if encrypt is not None:
        rd[f"ChaCha20/test_wycheproof_encrypt/{str(mode)}"] = _test_wycheproof_encrypt(
            encrypt, mode
        )
    if decrypt is not None:
        rd[f"ChaCha20/test_wycheproof_decrypt/{str(mode)}"] = _test_wycheproof_decrypt(
            decrypt, mode
        )
    return rd


def _verify_file_chacha20(filename: str, operation: Operation) -> Results:
    """Verifies a file of ChaCha20 operations.

    Args:
        filename: The name of the file to test.
        operation: The operation performed.

    Returns:
        The results of testing the output in each line. Parsing errors (e.g. missing
        arguments) are counted as fails.
    """
    with open(filename, "r") as file:
        lines = file.readlines()
    logger.debug("Read %s lines from %s.", len(lines), filename)

    results = Results(
        "ChaCha20",
        "verify_file",
        "Tests the output of an implementation.",
        {"filename": filename, "mode": Mode.CHACHA20, "operation": operation},
    )

    # Unpack lines with pattern matching as there are a variable number of arguments.
    if operation == Operation.ENCRYPT:
        for tid, line in track(enumerate(lines, start=1), "Testing file"):
            if line.startswith("#"):
                continue
            info = DebugInfo(
                tid, TestType.VALID, ["UserInput"], comment=f"Line number {tid}"
            )
            match line.rstrip().split("/"):
                case (k, p, c, n, i):
                    key, plaintext, ciphertext, nonce = map(
                        lambda d: bytes.fromhex(d), (k, p, c, n)
                    )
                    init_counter = int(i)
                case (k, p, c, n):
                    key, plaintext, ciphertext, nonce = map(
                        lambda d: bytes.fromhex(d), (k, p, c, n)
                    )
                    init_counter = 0
                case _ as args:
                    info.error_msg = (
                        f"Wrong number of arguments: got {len(args)}, expected 3 or 4"
                    )
                    results.add(ChaCha20Data(info, operation, None, None, None))
                    continue
            ct = _encrypt(
                Mode.CHACHA20, key, plaintext, nonce, init_counter=init_counter
            )
            if ciphertext == ct:
                info.result = True
            else:
                info.error_msg = "Wrong ciphertext"
            results.add(
                ChaCha20Data(
                    info, operation, key, plaintext, ct, ciphertext, nonce, init_counter
                )
            )
    else:
        for tid, line in track(enumerate(lines, start=1), "Testing file"):
            if line.startswith("#"):
                continue
            info = DebugInfo(
                tid, TestType.VALID, ["UserInput"], comment=f"Line number {tid}"
            )
            match line.rstrip().split("/"):
                case (k, c, p, n, i):
                    key, ciphertext, plaintext, nonce = map(
                        lambda d: bytes.fromhex(d), (k, c, p, n)
                    )
                    init_counter = int(i)
                case (k, c, p, n):
                    key, ciphertext, plaintext, nonce = map(
                        lambda d: bytes.fromhex(d), (k, c, p, n)
                    )
                    init_counter = 0
                case _ as args:
                    info.error_msg = (
                        f"Wrong number of arguments: got {len(args)}, expected 3 or 4"
                    )
                    results.add(ChaCha20Data(info, operation, None, None, None))
                    continue
            pt = _decrypt(
                Mode.CHACHA20, key, ciphertext, nonce, init_counter=init_counter
            )
            if plaintext == pt:
                info.result = True
            else:
                info.error_msg = "Wrong plaintext"
            results.add(
                ChaCha20Data(
                    info,
                    operation,
                    key,
                    ciphertext,
                    pt,
                    plaintext,
                    nonce,
                    init_counter=init_counter,
                )
            )

    return results


def _verify_file_chacha20_poly1305(filename: str, operation: Operation) -> Results:
    """Verifies a file of ChaCha20 operations.

    Args:
        filename: The name of the file to test.
        operation: The operation performed.

    Returns:
        The results of testing the output in each line. Parsing errors (e.g. missing
        arguments) are counted as fails.
    """
    with open(filename, "r") as file:
        lines = file.readlines()
    logger.debug("Read %s lines from %s.", len(lines), filename)

    results = Results(
        "ChaCha20",
        "verify_file",
        "Tests the output of an implementation.",
        {"filename": filename, "mode": Mode.CHACHA20_POLY1305, "operation": operation},
    )

    aad: bytes | None
    # Unpack lines with pattern matching as there are a variable number of arguments.
    if operation == Operation.ENCRYPT:
        for tid, line in track(enumerate(lines, start=1), "Testing file"):
            if line.startswith("#"):
                continue
            info = DebugInfo(
                tid, TestType.VALID, ["UserInput"], comment=f"Line number {tid}"
            )
            match line.rstrip().split("/"):
                case (k, p, c, n, m, a):
                    key, plaintext, ciphertext, nonce, mac, aad = map(
                        lambda d: bytes.fromhex(d), (k, p, c, n, m, a)
                    )
                case (k, p, c, n, m):
                    key, plaintext, ciphertext, nonce, mac = map(
                        lambda d: bytes.fromhex(d), (k, p, c, n, m)
                    )
                    aad = None
                case _:
                    info.error_msg = (
                        f"Wrong number of arguments: got {len(line)}, expected 3 or 4"
                    )
                    results.add(ChaCha20Data(info, operation, None, None, None))
                    continue
            ct, mt = _encrypt(
                Mode.CHACHA20_POLY1305,
                key,
                plaintext,
                nonce,
                aad=aad,
            )
            if ciphertext == ct and mac == mt:
                info.result = True
            elif ciphertext != ct and mac != mt:
                info.error_msg = "Wrong ciphertext and MAC"
            elif ciphertext != ct:
                info.error_msg = "Wrong ciphertext"
            else:
                info.error_msg = "Wrong MAC"
            results.add(
                ChaCha20Data(
                    info,
                    operation,
                    key,
                    plaintext,
                    ct,
                    ciphertext,
                    nonce,
                    aad=aad,
                    expected_mac=mt,
                    mac=mac,
                )
            )
    else:
        for tid, line in track(enumerate(lines, start=1), "Testing file"):
            if line.startswith("#"):
                continue
            info = DebugInfo(
                tid, TestType.VALID, ["UserInput"], comment=f"Line number {tid}"
            )
            match line.rstrip().split("/"):
                case (k, c, p, n, m, a):
                    key, ciphertext, plaintext, nonce, mac, aad = map(
                        lambda d: bytes.fromhex(d), (k, c, p, n, m, a)
                    )
                case (k, c, p, n, m):
                    key, ciphertext, plaintext, nonce, mac = map(
                        lambda d: bytes.fromhex(d), (k, c, p, n, m)
                    )
                    aad = None
                case _:
                    info.error_msg = (
                        f"Wrong number of arguments: got {len(line)}, expected 3 or 4"
                    )
                    results.add(ChaCha20Data(info, operation, None, None, None))
                    continue
            pt, st = _decrypt(
                Mode.CHACHA20_POLY1305, key, ciphertext, nonce, mac=mac, aad=aad
            )
            if st and plaintext == pt:
                info.result = True
            elif not st:
                info.error_msg = "Invalid MAC/ciphertext"
            else:
                info.error_msg = "Wrong plaintext"
            results.add(
                ChaCha20Data(
                    info,
                    operation,
                    key,
                    ciphertext,
                    pt,
                    plaintext,
                    nonce,
                    expected_mac=mac,
                    aad=aad,
                )
            )

    return results


def verify_file(filename: str, mode: Mode, operation: Operation) -> Results:
    r"""Tests the output of an implementation.

    Tests an implementation from a set of inputs passed to it and the outputs it
    returned. These inputs are passed to the internal implementation and the results are
    compared to the outputs given.

    Format:
        - One line per operation.
        - Lines are separated by newlines (``\n``).
        - Lines that start with # are counted as comments and ignored.
        - Arguments written in hexadecimal and separated by slashes.
        - Arguments in brackets are optional. If omitted, don't include the trailing
          slash.
        - For ChaCha20, the order of the arguments is:

        .. code::

            key/input/output/nonce[/init_counter]

        - For ChaCha20-Poly1305, the order of the arguments is:

        .. code:: text

            key/input/output/nonce/mac[/aad]

        - Where:
            - ``input`` is the plaintext when encrypting (resp. the ciphertext when
              decrypting).
            - ``output`` is the ciphertext when encrypting (resp. the plaintext when
              decrypting).
            - ``nonce`` is the nonce used for that operation.
            - ``init_counter`` is the initial position in the keystream to seek before
              the operation.
            - ``mac`` is the MAC tag. When encrypting, it is compared to the MAC
              returned by the internal implementation. When decrypting it is used to
              authenticate the ciphertext.
            - ``aad`` is the associated data. Can be empty.

    Args:
        filename: The name of the file to test.
        mode: The mode of operation to use.
        operation: The operation being tested, 'encrypt' or 'decrypt'.

    Returns:
        The results of running the inputs of each line with the internal implementation,
        and comparing both outputs to see if they match.

        Parsing errors are considered as test failures.

    Example:
        Let's generate 10 random tuples of (key, plaintext, nonce), encrypt the
        plaintexts using PyCryptodome, and write everything to a file.

        >>> import random
        >>> from crypto_condor.primitives import ChaCha20
        >>> from Crypto.Cipher import ChaCha20 as pyChaCha20
        >>> filename = "/tmp/crypto-condor-test/chacha20-verify.txt"
        >>> with open(filename, "w") as file:
        ...     for _ in range(10):
        ...         # Pick random values
        ...         key = random.randbytes(32)
        ...         plaintext = random.randbytes(64)
        ...         nonce = random.randbytes(12)
        ...         # Encrypt
        ...         cipher = pyChaCha20.new(key=key, nonce=nonce)
        ...         ciphertext = cipher.encrypt(plaintext)
        ...         # Convert to hexadecimal
        ...         kh, nh = key.hex(), nonce.hex()
        ...         ph, ch = plaintext.hex(), ciphertext.hex()
        ...         # Create the line to write, note the absent init_counter
        ...         line = f"{kh}/{ph}/{ch}/{nh}\n"
        ...         _ = file.write(line)

        Now we can test the file.

        >>> mode = ChaCha20.Mode.CHACHA20
        >>> operation = ChaCha20.Operation.ENCRYPT
        >>> results = ChaCha20.verify_file(filename, mode, operation)
        Testing ...
        >>> assert results.check()
    """
    if not Path(filename).is_file():
        raise FileNotFoundError(f"No file named {filename}")

    if mode == Mode.CHACHA20:
        return _verify_file_chacha20(filename, operation)
    else:
        return _verify_file_chacha20_poly1305(filename, operation)


def _run_python(
    mode: Mode, resilience: bool, encrypt: bool, decrypt: bool
) -> ResultsDict:
    """Runs the Python ChaCha20 wrapper.

    Args:
        mode: The mode of operation to test.
        resilience: Whether to run resilience test vectors.
        encrypt: Whether to test the encryption.
        decrypt: Whether to test the decryption.

    Raises:
        FileNotFoundError: If the wrapper couldn't be found or imported.
    """
    wrapper = Path().cwd() / "chacha20_wrapper.py"
    if not wrapper.exists():
        raise FileNotFoundError(
            "Can't find chacha20_wrapper.py in the current directory."
        )

    logger.info("Running Python ChaCha20 wrapper")

    # Add CWD to the path, at the beginning in case this is called more than
    # once, since the previous CWD would have priority.
    sys.path.insert(0, str(Path.cwd()))

    # Before importing the wrapper we check if it's already in the loaded
    # modules, in which case we want to reload it or we would be testing the
    # wrapper loaded previously.
    imported = "chacha20_wrapper" in sys.modules.keys()

    # Import it normally.
    try:
        chacha20_wrapper = importlib.import_module("chacha20_wrapper")
    except ModuleNotFoundError as error:
        logger.debug(error)
        raise FileNotFoundError("Can't load the wrapper!") from error

    # Then reload it if necessary.
    if imported:
        logger.debug("Reloading the ChaCha20 Python wrapper")
        chacha20_wrapper = importlib.reload(chacha20_wrapper)

    encrypt_function = chacha20_wrapper.encrypt if encrypt else None
    decrypt_function = chacha20_wrapper.decrypt if decrypt else None
    result_dict = test(encrypt_function, decrypt_function, mode, resilience=resilience)

    # To de-clutter the path, remove the CWD.
    sys.path.remove(str(Path.cwd()))

    return result_dict


def run_wrapper(
    language: Wrapper,
    mode: Mode,
    *,
    resilience: bool = True,
    encrypt: bool = True,
    decrypt: bool = True,
) -> ResultsDict:
    """Runs a wrapper.

    Args:
        language: The language of the wrapper.
        mode: The mode of operation to test.

    Keyword Args:
        resilience: Whether to run resilience test vectors.
        encrypt: Whether to test the encryption.
        decrypt: Whether to test the decryption.

    Returns:
        The results from :func:`test`.
    """
    match language:
        case Wrapper.PYTHON:
            return _run_python(mode, resilience, encrypt, decrypt)
        case _:  # pragma: no cover (mypy)
            raise ValueError(f"Unsupported language {language}")


# --------------------------- Lib hook functions --------------------------------------
def _hook_enc(lib: ctypes.CDLL, function: str):
    """Tests a hook for ChaCha20 encryption."""
    logger.info("Testing %s", function)

    func = lib[function]
    func.argtypes = [
        ctypes.POINTER(ctypes.c_uint8),  # buffer
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_uint8),  # key
        ctypes.POINTER(ctypes.c_uint8),  # buffer
        ctypes.c_size_t,
        ctypes.c_uint64,
    ]
    func.restype = None

    # Key size is fixed so we can create the type in advance.
    key_t = ctypes.c_uint8 * 32

    def _enc(key: bytes, plaintext: bytes, nonce: bytes, init_counter: int = 0):
        buf_t = ctypes.c_uint8 * len(plaintext)
        nonce_t = ctypes.c_uint8 * len(nonce)

        key_arr = key_t.from_buffer_copy(key)
        buffer = buf_t.from_buffer_copy(plaintext)
        nonce_arr = nonce_t.from_buffer_copy(nonce)

        func(
            buffer,
            buffer._length_,
            key_arr,
            nonce_arr,
            nonce_arr._length_,
            init_counter,
        )
        return bytes(buffer)

    return test(_enc, None, Mode.CHACHA20)  # type: ignore[arg-type]


def _hook_dec(lib: ctypes.CDLL, function: str):
    """Tests a hook for ChaCha20 decryption."""
    logger.info("Testing %s", function)

    func = lib[function]
    func.argtypes = [
        ctypes.POINTER(ctypes.c_uint8),  # buffer
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_uint8),  # key
        ctypes.POINTER(ctypes.c_uint8),  # buffer
        ctypes.c_size_t,
        ctypes.c_uint64,
    ]
    func.restype = None

    # Key size is fixed so we can create the type in advance.
    key_t = ctypes.c_uint8 * 32

    def _dec(key: bytes, ciphertext: bytes, nonce: bytes, init_counter: int = 0):
        buf_t = ctypes.c_uint8 * len(ciphertext)
        nonce_t = ctypes.c_uint8 * len(nonce)

        key_arr = key_t.from_buffer_copy(key)
        buffer = buf_t.from_buffer_copy(ciphertext)
        nonce_arr = nonce_t.from_buffer_copy(nonce)

        func(
            buffer,
            buffer._length_,
            key_arr,
            nonce_arr,
            nonce_arr._length_,
            init_counter,
        )
        return bytes(buffer)

    return test(None, _dec, Mode.CHACHA20)  # type: ignore[arg-type]


def _hook_enc_poly1305(lib: ctypes.CDLL, function: str):
    """Tests a hook for ChaCha20-Poly1305 encryption."""
    logger.info("Testing %s", function)

    func = lib[function]
    func.argtypes = [
        ctypes.POINTER(ctypes.c_uint8),  # buffer
        ctypes.c_size_t,
        ctypes.c_uint8 * 16,  # mac
        ctypes.c_uint8 * 32,  # key
        ctypes.POINTER(ctypes.c_uint8),  # nonce
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_uint8),  # aad
        ctypes.c_size_t,
    ]
    func.restype = None

    key_t = ctypes.c_uint8 * 32
    mac_t = ctypes.c_uint8 * 16

    def _enc(key: bytes, plaintext: bytes, nonce: bytes, aad: bytes | None):
        buf_t = ctypes.c_uint8 * len(plaintext)
        nonce_t = ctypes.c_uint8 * len(nonce)

        if aad:
            aad_t = ctypes.c_uint8 * len(aad)
            aad_arr = aad_t.from_buffer_copy(aad)
        else:
            aad_arr = None

        key_arr = key_t.from_buffer_copy(key)
        buffer = buf_t.from_buffer_copy(plaintext)
        nonce_arr = nonce_t.from_buffer_copy(nonce)
        mac_arr = mac_t()

        func(
            buffer,
            buffer._length_,
            mac_arr,
            key_arr,
            nonce_arr,
            len(nonce),
            aad_arr,
            len(aad) if aad else 0,
        )
        return (bytes(buffer), bytes(mac_arr))

    return test(_enc, None, Mode.CHACHA20_POLY1305)  # type: ignore


def _hook_dec_poly1305(lib: ctypes.CDLL, function: str):
    """Tests a hook for ChaCha20-Poly1305 decryption."""
    logger.info("Testing %s", function)

    func = lib[function]
    func.argtypes = [
        ctypes.POINTER(ctypes.c_uint8),  # buffer
        ctypes.c_size_t,
        ctypes.c_uint8 * 32,  # key
        ctypes.POINTER(ctypes.c_uint8),  # nonce
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_uint8),  # aad
        ctypes.c_size_t,
        ctypes.c_uint8 * 16,  # mac
    ]
    func.restype = ctypes.c_int

    key_t = ctypes.c_uint8 * 32
    mac_t = ctypes.c_uint8 * 16

    def _dec(
        key: bytes, ciphertext: bytes, nonce: bytes, mac: bytes, aad: bytes | None
    ):
        buf_t = ctypes.c_uint8 * len(ciphertext)
        nonce_t = ctypes.c_uint8 * len(nonce)
        if aad:
            aad_t = ctypes.c_uint8 * len(aad)
            aad_arr = aad_t.from_buffer_copy(aad)
        else:
            aad_arr = None

        key_arr = key_t.from_buffer_copy(key)
        buffer = buf_t.from_buffer_copy(ciphertext)
        nonce_arr = nonce_t.from_buffer_copy(nonce)
        mac_arr = mac_t.from_buffer_copy(mac)

        rc = func(
            buffer,
            buffer._length_,
            key_arr,
            nonce_arr,
            len(nonce),
            aad_arr,
            len(aad) if aad else 0,
            mac_arr,
        )

        if rc == 0:
            return (bytes(buffer), True)
        elif rc == -1:
            return (None, False)
        else:
            raise ValueError(f"Invalid return value {rc} (expected 0 or -1)")

    return test(None, _dec, Mode.CHACHA20_POLY1305)  # type: ignore


def test_hook(lib: ctypes.CDLL, functions: list[str]) -> ResultsDict:
    """Tests function from a shared library.

    Args:
        lib: The loaded library.
        functions: A list of CC_ChaCha20 functions to test.
    """
    logger.info("Found functions %s", ", ".join(functions))

    rd = ResultsDict()

    for function in functions:
        match function.split("_"):
            case ["CC", "ChaCha20", ("encrypt" | "decrypt") as operation]:
                if operation == "encrypt":
                    rd |= _hook_enc(lib, function)
                else:
                    rd |= _hook_dec(lib, function)
            case ["CC", "ChaCha20", "Poly1305", ("encrypt" | "decrypt") as operation]:
                if operation == "encrypt":
                    rd |= _hook_enc_poly1305(lib, function)
                else:
                    rd |= _hook_dec_poly1305(lib, function)
            case _:
                logger.warning(
                    "Ignored function %s as it does not match the convention", function
                )

    return rd
