"""Module to test AES implementations.

The :mod:`crypto_condor.primitives.AES` module can test implementations of :doc:`AES
</method/AES>` encryption and decryption using several modes of operations with the
:func:`test_encrypt` and :func:`test_decrypt` functions. Supported modes are defined by
the :enum:`Mode` enum.
"""

from __future__ import annotations

import importlib
import json
import logging
import subprocess
import sys
import zipfile
import zlib
from importlib import resources
from pathlib import Path
from typing import Any, Literal, Protocol, overload

import _cffi_backend
import attrs
import cffi
import strenum
from Crypto.Cipher import AES as pycryptoAES
from Crypto.Util import Padding
from rich.progress import track

from crypto_condor.primitives.common import (
    CiphertextAndTag,
    PlaintextAndBool,
    Results,
    ResultsDict,
    TestInfo,
    TestType,
    get_appdata_dir,
)
from crypto_condor.vectors._aes.aes_pb2 import AesTest, AesVectors
from crypto_condor.vectors.aes import KeyLength, Mode

logger = logging.getLogger(__name__)


def __dir__():  # pragma: no cover
    return [
        # Enums
        KeyLength.__name__,
        Mode.__name__,
        Wrapper.__name__,
        Operation.__name__,
        # Protocols
        Encrypt.__name__,
        Decrypt.__name__,
        # Test functions
        test_encrypt.__name__,
        test_decrypt.__name__,
        test_output_encrypt.__name__,
        test_output_decrypt.__name__,
        test_lib.__name__,
        # Runners
        run_python_wrapper.__name__,
    ]


# --------------------------- Compile the AES primitive -------------------------------
_AES_LIB_COMPILATION_FAILED = False
"""Variable to keep track of whether we tried to install the library and it failed."""
_AES_FFI: cffi.FFI | None = None
"""The FFI of the AES shared library. If None, call _get_aes_lib."""
_AES_LIB: _cffi_backend.Lib | None = None
"""The dlopen'ed library. If None, call _get_aes_lib."""


def _get_lib_dir() -> Path:
    return get_appdata_dir() / "AES"


def _get_aes_lib() -> tuple[cffi.FFI | None, _cffi_backend.Lib | None]:
    """Install or find the shared library for our implementation of AES.

    crypto-condor has its own implementation of AES, which supports the classic modes of
    operation. It is written in C: to use it, the source is copied to the path returned
    by :func:`_get_lib_dir` and compiled locally.

    Its functions are accessed through cffi: this function cdef's the exposed functions
    and structures and loads the library with dlopen. The idea is to avoid the cost of
    these operations each time _encrypt or _decrypt are called, which is
    non-negligible: test_AES.py::test_mode[ECB] took roughly 15s when cdef-ing and
    loading the library inside _encrypt/_decrypt. With this approach, the same test
    takes 0.1s. (And with the previous approach of generating and calling an executable,
    the CI reported ~4.5s for ECB.)

    Returns:
        A tuple containing the FFI and Lib objects, or (None, None) if the installation
        failed.
    """
    global _AES_LIB_COMPILATION_FAILED

    global _AES_FFI, _AES_LIB

    if _AES_FFI is not None and _AES_LIB is not None:
        return _AES_FFI, _AES_LIB

    if _AES_LIB_COMPILATION_FAILED:
        return None, None

    rsc = resources.files("crypto_condor") / "primitives/_aes"
    lib_zip = rsc / "AES.zip"

    lib_dir = _get_lib_dir()
    if not lib_dir.is_dir():
        _msg = (
            "AES directory not found:"
            " crypto-condor uses its own C implementation of AES for the classic modes"
            " of operation, which has to be compiled and installed locally."
        )
        logger.warning(_msg)
        logger.warning("Installation will be done at %s", str(lib_dir))
        with zipfile.ZipFile(str(lib_zip), "r") as myzip:
            myzip.extractall(lib_dir)
        logger.info("Copied AES source files")

    lib_file = lib_dir / "aes.so"
    changes = False

    # If there is already a shared library, check for changes to the source files to
    # know when to update it. We can use the CRC32 checksums included in the zip file to
    # compare files.
    if lib_file.is_file():
        with zipfile.ZipFile(str(lib_zip), "r") as myzip:
            for info in myzip.infolist():
                dst = lib_dir / info.filename
                if not dst.is_file():
                    # Found a new file in the zip archive.
                    changes = True
                    break
                # TODO: check for lingering files which may cause compilation problems.
                data = dst.read_bytes()
                if zlib.crc32(data) != info.CRC:
                    changes = True
                    break
            # Don't try to be smart, just copy everything.
            if changes:
                myzip.extractall(lib_dir)
                logger.info("Updated AES source files")

    if not lib_file.is_file() or changes:
        if changes:
            logger.info("AES shared library is outdated, updating")
        else:
            logger.info("AES shared library not found, installing")
        try:
            subprocess.run(
                ["make", "aes.so"],
                cwd=lib_dir,
                check=True,
                timeout=10.0,
                capture_output=True,
            )
        except subprocess.CalledProcessError as error:
            logger.error("Failed to compile AES shared library")
            logger.debug("Error: %s", str(error))
            _AES_LIB_COMPILATION_FAILED = True
            return None, None
        logger.info("AES library installed")

    _AES_FFI = cffi.FFI()
    _AES_FFI.cdef(
        """
        struct AES_ctx {
            uint8_t round_key[240];
            uint8_t Iv[16];
            uint8_t Nk;
            uint8_t Nr;
        };
        void AES_init_ctx(struct AES_ctx *ctx,
                          const uint8_t *key, const size_t key_length);
        void AES_init_ctx_iv(struct AES_ctx *ctx,
                             const uint8_t *key, const size_t key_length,
                             const uint8_t *iv);
        void AES_ECB_encrypt_buffer(const struct AES_ctx *ctx,
                                    uint8_t *buffer, size_t length);
        void AES_CBC_encrypt_buffer(const struct AES_ctx *ctx,
                                    uint8_t *buffer, size_t length);
        void AES_CFB_encrypt_buffer(struct AES_ctx *ctx,
                                    uint8_t *buffer, size_t length,
                                    size_t segment_size);
        void AES_ECB_decrypt_buffer(const struct AES_ctx *ctx,
                                    uint8_t *buffer, size_t length);
        void AES_CBC_decrypt_buffer(const struct AES_ctx *ctx,
                                    uint8_t *buffer, size_t length);
        void AES_CFB_decrypt_buffer(struct AES_ctx *ctx,
                                    uint8_t *buffer, size_t length,
                                    size_t segment_size);
        void AES_CTR_xcrypt_buffer(struct AES_ctx *ctx, uint8_t *buffer, size_t length);
        """
    )
    _AES_LIB = _AES_FFI.dlopen(str(lib_file.absolute()))

    return _AES_FFI, _AES_LIB


# --------------------------- Enums ---------------------------------------------------


class Wrapper(strenum.StrEnum):
    """Supported languages for wrappers."""

    PYTHON = "Python"


class Operation(strenum.StrEnum):
    """Operations supported for AES.

    As a symmetric cipher, AES can encrypt and decrypt messages. This enum is used to
    choose between these operations for the :func:`verify_file` function.
    """

    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"


# --------------------------- Protocols -----------------------------------------------


class Encrypt(Protocol):
    """Represents a function that encrypts with AES.

    Encryption functions must behave like one of the :attr:`__call__` functions to be
    tested with this module. Each correspond to one or more modes of operation. In
    order:

    - ECB
    - CBC or CTR or CFB8 or CFB128
    - CCM or GCM
    """

    # ECB
    @overload
    def __call__(self, key: bytes, plaintext: bytes) -> bytes: ...

    # CBC / CTR / CFB
    @overload
    def __call__(self, key: bytes, plaintext: bytes, *, iv: bytes) -> bytes: ...

    # CCM / GCM
    @overload
    def __call__(
        self,
        key: bytes,
        plaintext: bytes,
        *,
        iv: bytes | None,
        aad: bytes | None,
        mac_len: int = 0,
    ) -> CiphertextAndTag: ...

    def __call__(
        self,
        key: bytes,
        plaintext: bytes,
        *,
        iv: bytes | None = None,
        aad: bytes | None = None,
        mac_len: int = 0,
    ) -> bytes | CiphertextAndTag:
        """Encrypts with AES.

        Args:
            key: The symmetric key.
            plaintext: The input to encrypt.

        Keyword Args:
            iv: (All modes except ECB) The IV or nonce.
            aad: (CCM/GCM) The associated data.
            mac_len: (CCM/GCM) The length of the authentication tag.

        Returns:
            (ECB/CBC/CTR/CFB) The resulting ciphertext.

            (CCM/GCM) A (ciphertext, tag) tuple.
        """
        ...  # pragma: no cover (nothing to cover)


class Decrypt(Protocol):
    """Represents a function that decrypts with AES.

    Decryption functions must behave like one of the :attr:`__call__` functions to be
    tested with this module. Each correspond to one or more modes of operation. In
    order:

    - ECB
    - CBC or CTR or CFB8 or CFB128
    - CCM or GCM
    """

    # ECB
    @overload
    def __call__(self, key: bytes, ciphertext: bytes) -> bytes: ...

    # CBC / CTR
    @overload
    def __call__(self, key: bytes, ciphertext: bytes, *, iv: bytes | None) -> bytes: ...

    # CCM / GCM
    @overload
    def __call__(
        self,
        key: bytes,
        ciphertext: bytes,
        *,
        iv: bytes | None,
        aad: bytes | None,
        mac: bytes | None,
        mac_len: int = 0,
    ) -> PlaintextAndBool: ...

    def __call__(
        self,
        key: bytes,
        ciphertext: bytes,
        *,
        iv: bytes | None = None,
        aad: bytes | None = None,
        mac: bytes | None = None,
        mac_len: int = 0,
    ) -> bytes | PlaintextAndBool:
        """Decrypts with AES.

        Args:
            key: The symmetric key.
            ciphertext: The input to decrypt.

        Keyword Args:
            iv: (All modes except ECB) The IV or nonce.
            aad: (CCM/GCM) The associated data.
            mac: (CCM/GCM) The authentication tag.
            mac_len: (CCM/GCM) The length of the authentication tag in bytes.

        Returns:
            (ECB/CBC/CTR/CFB) The resulting plaintext.

            (CCM/GCM) If the MAC is valid it returns (plaintext, True). Otherwise the
            plaintext should not be release so it returns (None, False).

        Notes:
            We decided to return None when the MAC verification fails to differentiate
            from the case where the message is empty, which is a valid case, and is
            tested by some test vectors. It serves as a clear sign that even in case we
            don't test the verification status "this is not the plaintext you're looking
            for".
        """
        ...  # pragma: no cover (nothing to cover)


# ---------------------- Dataclasses---------------------------------------------


@attrs.define
class EncData:
    """Debug data for :func:`test_encrypt`.

    Args:
        key: The key used.
        pt: The plaintext to encrypt.
        ct: The expected ciphertext.
        iv: The IV or nonce.
        aad: Associated data, only for AEAD modes.
        tag: The expected tag in AEAD modes.
        ret_ct: The ciphertext returned by the implementation.
        ret_tag: The tag returned by the AEAD implementation.
    """

    key: bytes
    pt: bytes
    ct: bytes
    iv: bytes | None
    aad: bytes | None
    tag: bytes | None
    ret_ct: bytes | None = None
    ret_tag: bytes | None = None

    def __str__(self) -> str:
        """Returns a string representation of the present fields."""
        s = ""
        s += f"key = {self.key.hex()}\n"
        s += f"pt = {self.pt.hex()}\n"

        if self.iv is not None:
            s += f"iv = {self.iv.hex()}\n"
        if self.aad is not None:
            s += f"aad = {self.aad.hex()}\n"

        s += f"ct = {self.ct.hex()}\n"
        if self.ret_ct is not None:
            s += f"returned ct = {self.ret_ct.hex()}\n"
        else:
            s += "returned ct = <none>\n"

        if self.tag is not None:
            s += f"tag = {self.tag.hex()}\n"
        if self.ret_tag is not None:
            s += f"returned tag = {self.ret_tag.hex()}\n"
        else:
            s += "returned tag = <none>\n"

        return s


@attrs.define
class DecData:
    """Debug data for :func:`test_decrypt`."""

    key: bytes
    ct: bytes
    pt: bytes
    iv: bytes | None
    aad: bytes | None
    tag: bytes | None
    ret_pt: bytes | None = None
    ret_valid_tag: bool | None = None

    def __str__(self) -> str:
        """Returns a string representation of the present fields."""
        s = ""
        s += f"key = {self.key.hex()}\n"
        s += f"ct = {self.ct.hex()}\n"

        if self.iv is not None:
            s += f"iv = {self.iv.hex()}\n"
        if self.aad is not None:
            s += f"aad = {self.aad.hex()}\n"

        s += f"pt = {self.pt.hex()}\n"
        if self.ret_pt is not None:
            s += f"returned pt = {self.ret_pt.hex()}\n"
        else:
            s += "returned pt = <none>\n"

        if self.tag is not None:
            s += f"tag = {self.tag.hex()}\n"
        if self.ret_valid_tag is not None:
            s += f"valid tag = {self.ret_valid_tag}\n"

        return s


class ParsingError(Exception):
    """Exception for errors while parsing output files."""

    pass


# ----------------------------- AES functions -----------------------------------------


# ECB
@overload
def _encrypt(mode: Literal[Mode.ECB], key: bytes, plaintext: bytes) -> bytes: ...


# CBC / CTR
@overload
def _encrypt(
    mode: Literal[Mode.CBC, Mode.CBC_PKCS7, Mode.CTR, Mode.CFB, Mode.CFB8, Mode.CFB128],
    key: bytes,
    plaintext: bytes,
    *,
    iv: bytes | None,
) -> bytes: ...


# CCM / GCM
@overload
def _encrypt(
    mode: Literal[Mode.CCM, Mode.GCM],
    key: bytes,
    plaintext: bytes,
    *,
    iv: bytes | None,
    aad: bytes | None,
    mac_len: int = 0,
) -> CiphertextAndTag: ...


def _encrypt(
    mode: Mode,
    key: bytes,
    plaintext: bytes,
    *,
    iv: bytes | None = None,
    aad: bytes | None = None,
    mac_len: int = 0,
) -> bytes | CiphertextAndTag:
    """Encrypts with AES.

    Args:
        mode: The mode of operation.
        key: The symmetric key.
        plaintext: The input to encrypt.

    Keyword Args:
        iv: (All modes except ECB) The IV or nonce.
        aad: (CCM/GCM) The associated data.
        mac_len: (CCM/GCM) The length of the authentication tag.

    Returns:
        (ECB/CBC/CTR/CFB) The resulting ciphertext.

        (CCM/GCM) A (ciphertext, tag) tuple.

    Raises:
        subprocess.CalledProcessError: Raised by subprocess when an error running the
            AES implementation occurs.
        ValueError: Raised by various value checks (missing IV, etc.).
    """
    # Deal with PyCryptodome modes first.
    if mode == Mode.CCM:
        if iv is None:  # pragma: no cover (requires error)
            raise ValueError("CCM requires a nonce (iv)")
        if mac_len is None:
            raise ValueError("CCM requires mac_len")
        ccm = pycryptoAES.new(key, pycryptoAES.MODE_CCM, nonce=iv, mac_len=mac_len)
        if aad is not None:
            ccm.update(aad)
        return ccm.encrypt_and_digest(plaintext)
    elif mode == Mode.GCM:
        if iv is None:  # pragma: no cover (requires error)
            raise ValueError("GCM requires a nonce (iv)")
        if len(iv) == 0:
            raise ValueError("Zero length nonce is not valid")
        if mac_len:
            gcm = pycryptoAES.new(key, pycryptoAES.MODE_GCM, nonce=iv, mac_len=mac_len)
        else:
            gcm = pycryptoAES.new(key, pycryptoAES.MODE_GCM, nonce=iv)
        if aad is not None:
            gcm.update(aad)
        return gcm.encrypt_and_digest(plaintext)

    ffi, lib = _get_aes_lib()
    # TODO: add PyCryptodome as fallback
    if ffi is None or lib is None:
        raise FileNotFoundError("AES library not found")

    ctx = ffi.new("struct AES_ctx *")
    ctx_key = ffi.new(f"uint8_t[{len(key)}]", key)
    buf = ffi.new(f"uint8_t[{len(plaintext)}]", plaintext)

    # Deal with ECB first, so we can initialize a single IV if it's not ECB.
    if mode == Mode.ECB:
        lib.AES_init_ctx(ctx, ctx_key, len(key))  # type: ignore[attr-defined]
        lib.AES_ECB_encrypt_buffer(ctx, buf, len(plaintext))  # type: ignore[attr-defined]
        return bytes(buf)

    if iv is None:
        raise ValueError(f"{str(mode)} mode requires an IV")
    ctx_iv = ffi.new("uint8_t[16]", iv)
    lib.AES_init_ctx_iv(ctx, ctx_key, len(key), ctx_iv)  # type: ignore[attr-defined]

    match mode:
        case Mode.CBC:
            lib.AES_CBC_encrypt_buffer(ctx, buf, len(plaintext))  # type: ignore[attr-defined]
        case Mode.CBC_PKCS7:
            # We re-create buf as we have to pad the plaintext before.
            pt = Padding.pad(plaintext, 16)
            buf = ffi.new(f"uint8_t[{len(pt)}]", pt)
            lib.AES_CBC_encrypt_buffer(ctx, buf, len(pt))  # type: ignore[attr-defined]
        case Mode.CFB | Mode.CFB8 | Mode.CFB128:
            segment_size = 8 if mode == Mode.CFB8 else 128
            lib.AES_CFB_encrypt_buffer(ctx, buf, len(plaintext), segment_size)  # type: ignore[attr-defined]
        case Mode.CTR:
            lib.AES_CTR_xcrypt_buffer(ctx, buf, len(plaintext))  # type: ignore[attr-defined]

    return bytes(buf)


@overload
def _decrypt(mode: Literal[Mode.ECB], key: bytes, ciphertext: bytes) -> bytes: ...


# CBC / CTR
@overload
def _decrypt(
    mode: Literal[Mode.CBC, Mode.CBC_PKCS7, Mode.CTR, Mode.CFB, Mode.CFB8, Mode.CFB128],
    key: bytes,
    ciphertext: bytes,
    *,
    iv: bytes | None,
) -> bytes: ...


# CCM / GCM
@overload
def _decrypt(
    mode: Literal[Mode.CCM, Mode.GCM],
    key: bytes,
    ciphertext: bytes,
    *,
    iv: bytes | None,
    aad: bytes | None,
    mac: bytes | None,
    mac_len: int = 0,
) -> PlaintextAndBool: ...


def _decrypt(
    mode: Mode,
    key: bytes,
    ciphertext: bytes,
    *,
    iv: bytes | None = None,
    aad: bytes | None = None,
    mac: bytes | None = None,
    mac_len: int = 0,
) -> bytes | PlaintextAndBool:
    """Decrypts with AES.

    Args:
        mode: The mode of operation.
        key: The symmetric key.
        ciphertext: The input to decrypt.

    Keyword Args:
        iv: (All modes except ECB) The IV or nonce.
        aad: (CCM/GCM) The associated data.
        mac: (CCM/GCM) The authentication tag.
        mac_len: (CCM/GCM) The length of the authentication tag in bytes.

    Returns:
        (ECB/CBC/CTR/CFB) The resulting plaintext.

        (CCM/GCM) If the MAC is valid it returns (plaintext, True). Otherwise the
        plaintext should not be release so it returns (None, False).

    Raises:
        subprocess.CalledProcessError: Raised by subprocess when an error running the
            AES implementation occurs.
        ValueError: Raised by various value checks (missing IV, etc).
    """
    # Deal with PyCryptodome modes first.
    if mode == Mode.CCM:
        if iv is None:  # pragma: no cover (requires error)
            raise ValueError("CCM requires a nonce (iv)")
        if mac is None:
            raise ValueError("CCM requires the MAC tag")
        if mac_len is None:
            raise ValueError("CCM requires mac_len")
        ccm = pycryptoAES.new(key, pycryptoAES.MODE_CCM, nonce=iv, mac_len=mac_len)
        if aad is not None:
            ccm.update(aad)
        try:
            p = ccm.decrypt_and_verify(ciphertext, mac)
            return p, True
        except ValueError:
            return None, False
    elif mode == Mode.GCM:
        if iv is None:  # pragma: no cover (requires error)
            raise ValueError("GCM requires a nonce (iv)")
        if len(iv) == 0:
            raise ValueError("Zero length nonce is not valid")
        if mac is None:
            raise ValueError("GCM requires the MAC tag")
        if mac_len:
            gcm = pycryptoAES.new(key, pycryptoAES.MODE_GCM, nonce=iv, mac_len=mac_len)
        else:
            gcm = pycryptoAES.new(key, pycryptoAES.MODE_GCM, nonce=iv)
        if aad is not None:
            gcm.update(aad)
        try:
            p = gcm.decrypt_and_verify(ciphertext, mac)
            return p, True
        except ValueError:
            return None, False

    ffi, lib = _get_aes_lib()
    # TODO: add PyCryptodome as fallback
    if ffi is None or lib is None:
        raise FileNotFoundError("AES library not found")

    ctx = ffi.new("struct AES_ctx *")
    ctx_key = ffi.new(f"uint8_t[{len(key)}]", key)
    buf = ffi.new(f"uint8_t[{len(ciphertext)}]", ciphertext)

    # Deal with ECB first, so we can initialize a single IV if it's not ECB.
    if mode == Mode.ECB:
        lib.AES_init_ctx(ctx, ctx_key, len(key))  # type: ignore[attr-defined]
        lib.AES_ECB_decrypt_buffer(ctx, buf, len(ciphertext))  # type: ignore[attr-defined]
        return bytes(buf)

    if iv is None:
        raise ValueError(f"{str(mode)} mode requires an IV")
    ctx_iv = ffi.new("uint8_t[16]", iv)
    lib.AES_init_ctx_iv(ctx, ctx_key, len(key), ctx_iv)  # type: ignore[attr-defined]

    match mode:
        case Mode.CBC:
            lib.AES_CBC_decrypt_buffer(ctx, buf, len(ciphertext))  # type: ignore[attr-defined]
        case Mode.CBC_PKCS7:
            lib.AES_CBC_decrypt_buffer(ctx, buf, len(ciphertext))  # type: ignore[attr-defined]
            # We return early as we have to unpad the plaintext.
            pt = Padding.unpad(bytes(buf), 16)
            return pt
        case Mode.CFB | Mode.CFB8 | Mode.CFB128:
            segment_size = 8 if mode == Mode.CFB8 else 128
            lib.AES_CFB_decrypt_buffer(ctx, buf, len(ciphertext), segment_size)  # type: ignore[attr-defined]
        case Mode.CTR:
            lib.AES_CTR_xcrypt_buffer(ctx, buf, len(ciphertext))  # type: ignore[attr-defined]

    return bytes(buf)


# ----------------------------- Test functions ----------------------------------------


# def _run_c(
#     wrapper: Path,
#     mode: Mode,
#     key_length: KeyLength,
#     compliance: bool,
#     resilience: bool,
#     encrypt: bool,
#     decrypt: bool,
#     iv_length: int,
# ) -> ResultsDict:
#     """Runs the C AES wrapper.
#
#     Args:
#         wrapper: The executable C wrapper to test.
#         mode: The mode of operation to test.
#         key_length: The length of the keys to use, in bits. Use 0 to test all lengths.
#         compliance: Whether to run compliance test vectors.
#         resilience: Whether to run resilience test vectors.
#         encrypt: Whether to test the encryption.
#         decrypt: Whether to test the decryption.
#         iv_length: The length of the IV to test. If 0, use any test vector available.
#
#     Raises:
#         FileNotFoundError: If the wrapper couldn't be found or imported.
#     """
#     exe = wrapper.absolute()
#
#     def enc(
#         key: bytes,
#         plaintext: bytes,
#         *,
#         iv: bytes | None = None,
#         aad: bytes | None = None,
#         mac_len: int = 0,
#     ) -> bytes | CiphertextAndTag:
#         """Function for encryption.
#
#         See :func:`~crypto_condor.primitives.AES._encrypt`.
#         """
#         args = [str(exe)]
#         args += ["--key", key.hex()]
#         args += ["--text", plaintext.hex()]
#         if iv is not None:
#             args += ["--iv", iv.hex()]
#         if aad is not None:
#             args += ["--aad", aad.hex() if aad else ""]
#         if mac_len > 0:
#             args += ["--tag-length", str(mac_len)]
#         if mode == Mode.CFB or mode == Mode.CFB128:
#             args += ["--segment-size", "128"]
#         elif mode == Mode.CFB8:
#             args += ["--segment-size", "8"]
#         if mode not in Mode.classic_modes():
#             args += ["--mode", "1"]
#         result = subprocess.run(args, capture_output=True, text=True)
#         if result.returncode != 0:
#             raise ValueError(result.stdout)
#
#         if mode in Mode.classic_modes():
#             ct = bytes.fromhex(result.stdout.strip())
#             return ct
#         else:
#             # remove trailing whitespace
#             out = result.stdout.rstrip()
#             # separate the two lines of output
#             lines = out.split("\n")
#             # get the ciphertext
#             if len(lines[0].split(" = ")) == 1:
#                 c = ""
#             else:
#                 _, c = lines[0].split(" = ")
#             # get the tag
#             _, t = lines[1].split(" = ")
#             return (bytes.fromhex(c), bytes.fromhex(t))
#
#     def dec(
#         key: bytes,
#         ciphertext: bytes,
#         *,
#         iv: bytes | None = None,
#         aad: bytes | None = None,
#         mac: bytes | None = None,
#         mac_len: int = 0,
#     ) -> bytes | PlaintextAndBool:
#         """Function for decryption.
#
#         See :func:`~crypto_condor.primitives.AES._decrypt`.
#         """
#         args = [str(exe)]
#         args += ["--key", key.hex()]
#         args += ["--text", ciphertext.hex()]
#         args += ["--decrypt"]
#         if iv is not None:
#             args += ["--iv", iv.hex()]
#         if aad is not None:
#             args += ["--aad", aad.hex() if aad else ""]
#         if mac is not None:
#             args += ["--tag", mac.hex() if mac else ""]
#         if mode == Mode.CFB or mode == Mode.CFB128:
#             args += ["--segment-size", "128"]
#         elif mode == Mode.CFB8:
#             args += ["--segment-size", "8"]
#         if mode not in Mode.classic_modes():
#             args += ["--mode", "1"]
#         result = subprocess.run(args, capture_output=True, text=True)
#         if result.returncode != 0:
#             raise ValueError(result.stdout)
#
#         if mode in Mode.classic_modes():
#             pt = bytes.fromhex(result.stdout.strip())
#             return pt
#         else:
#             # strip the trailing newline
#             out = result.stdout.rstrip()
#             # separate the two output lines
#             lines = out.split("\n")
#             # check the tag verification
#             _, v = lines[0].split(" = ")
#             if v == "FAIL":
#                 return (None, False)
#             # get the message
#             _, p = lines[1].split(" = ")
#             return (bytes.fromhex(p), True)
#
#     encrypt_function = enc if encrypt else None
#     decrypt_function = dec if decrypt else None
#     # TODO: fix type error by defining encrypt/decrypt depending on the mode of
#     # operation.
#     result_group = test(
#         encrypt_function,  # type: ignore
#         decrypt_function,  # type: ignore
#         mode,
#         key_length,
#         compliance=compliance,
#         resilience=resilience,
#         iv_length=iv_length,
#     )
#     return result_group


def _load_vectors(mode: Mode, keylen: KeyLength) -> list[AesVectors]:
    """Loads vectors for a given mode and key length.

    Returns:
        A list of vectors.
    """
    vectors_dir = importlib.resources.files("crypto_condor") / "vectors/_aes"
    vectors = list()

    sources_file = vectors_dir / "aes.json"
    with sources_file.open("r") as file:
        sources = json.load(file)

    if keylen == 0:
        klens = ["128", "192", "256"]
    else:
        klens = [str(keylen)]
    if mode == "CFB":
        mode = Mode.CFB128

    for klen in klens:
        for filename in sources[mode][str(klen)]:
            vectors_file = vectors_dir / "pb2" / filename
            _vec = AesVectors()
            logger.debug("Loading AES vectors from %s", str(filename))
            try:
                _vec.ParseFromString(vectors_file.read_bytes())
            except Exception:
                logger.exception("Failed to load AES vectors from %s", str(filename))
                continue
            vectors.append(_vec)

    return vectors


def _try_one_enc(enc: Encrypt, mode: Mode, test: AesTest) -> tuple[bytes, bytes | None]:
    ret_tag: bytes | None = None
    match mode:
        case Mode.ECB:
            ret_ct = enc(test.key, test.pt)
        case Mode.CBC | Mode.CTR | Mode.CFB | Mode.CFB8 | Mode.CFB128:
            ret_ct = enc(test.key, test.pt, iv=test.iv)
        case Mode.CBC_PKCS7:
            ret_ct = enc(test.key, test.pt, iv=test.iv)
            # TODO: improve this.
            ret_ct = ret_ct[: len(test.ct)]
        case Mode.GCM | Mode.CCM:
            ret_ct, ret_tag = enc(
                test.key, test.pt, iv=test.iv, aad=test.aad, mac_len=len(test.tag)
            )
    return ret_ct, ret_tag


def _try_one_dec(
    dec: Decrypt, mode: Mode, test: AesTest
) -> tuple[bytes | None, bool | None]:
    ret_pt: bytes | None
    ret_valid_tag: bool | None

    match mode:
        case Mode.ECB:
            ret_pt = dec(test.key, test.ct)
            ret_valid_tag = None
        case Mode.CBC | Mode.CTR | Mode.CFB | Mode.CFB8 | Mode.CFB128 | Mode.CBC_PKCS7:
            ret_pt = dec(test.key, test.ct, iv=test.iv)
            ret_valid_tag = None
        case Mode.GCM | Mode.CCM:
            ret_pt, ret_valid_tag = dec(
                test.key,
                test.ct,
                iv=test.iv,
                aad=test.aad,
                mac=test.tag,
                mac_len=len(test.tag),
            )
        case _:
            raise ValueError(f"Invalid mode: {mode}")

    return ret_pt, ret_valid_tag


def test_encrypt(
    encrypt: Encrypt,
    mode: Mode,
    keylen: KeyLength,
    *,
    compliance: bool = True,
    resilience: bool = False,
) -> ResultsDict:
    """Tests a function that encrypts with AES.

    Args:
        encrypt: The function to test.
        mode: The AES mode implemented. To more different modes, make separate calls to
            this function.
        keylen: The length of the keys to use.

    Keyword Args:
        compliance: Whether to use compliance test vectors.
        resilience: Whether to use resilience test vectors.

    Returns:
        A dictionary of results.

    Example:
        Let's test PyCryptodome with AES-256-GCM.

        We start by importing the AES module.

        >>> from crypto_condor.primitives import AES

        We need to wrap the encryption to match the signature of :protocol:`Encrypt`.

        >>> from Crypto.Cipher import AES as pycAES

        >>> def aes_gcm(
        ...     key: bytes,
        ...     plaintext: bytes,
        ...     *,
        ...     iv: bytes | None = None,
        ...     aad: bytes | None = None,
        ...     mac_len: int = 0,
        ... ) -> AES.CiphertextAndTag:
        ...     cipher = pycAES.new(key, pycAES.MODE_GCM, nonce=iv, mac_len=mac_len)
        ...     if aad is not None:
        ...         cipher.update(aad)
        ...     return cipher.encrypt_and_digest(plaintext)

        We define the parameters to test using the corresponding enums. We can use them
        directly but this simplifies the function call.

        >>> mode, keylen = AES.Mode.GCM, AES.KeyLength.AES256

        And now, we test the function.

        >>> res = AES.test_encrypt(aes_gcm, mode, keylen)
        [GCM][256][NIST CAVP] Testing encryption ...
        >>> assert res.check()
    """
    all_vectors = _load_vectors(mode, keylen)
    rd = ResultsDict()

    test: AesTest
    for vectors in all_vectors:
        if not vectors.encrypt:
            continue
        if not compliance and vectors.compliance:
            continue
        if not resilience and not vectors.compliance:
            continue

        results = Results.new(f"Tests AES-{mode} encryption", ["mode", "keylen"])
        rd.add(
            results,
            ["mode"],
            extra_values=[str(vectors.keylen), vectors.source.replace(" ", "_")],
        )

        for test in track(
            vectors.tests,
            rf"\[{mode}]\[{vectors.keylen}]\[{vectors.source}] Testing encryption",
        ):
            info = TestInfo.new_from_test(test, vectors.compliance)
            data = EncData(test.key, test.pt, test.ct, test.iv, test.aad, test.tag)

            try:
                ret_ct, ret_tag = _try_one_enc(encrypt, mode, test)
            except Exception as error:
                if test.type == "invalid":
                    # FIXME: overly permissive.
                    info.ok(data)
                else:
                    info.fail(f"Exception raised: {str(error)}", data)
                results.add(info)
                continue

            # Add returned values to debug data.
            data.ret_ct = ret_ct
            data.ret_tag = ret_tag

            # In all modes, check if ciphertext matches.
            is_same_ct = ret_ct == test.ct
            # Check if the tag matches only for AEAD modes, not classic ones.
            if mode in Mode.classic_modes():
                is_same_tag = True
            else:
                is_same_tag = ret_tag == test.tag

            match (is_same_ct and is_same_tag, test.type):
                case (True, TestType.VALID):
                    info.ok(data)
                case (False, TestType.VALID):
                    if not is_same_ct and not is_same_tag:
                        err_msg = "Wrong ciphertext and tag"
                    elif not is_same_ct:
                        err_msg = "Wrong ciphertext"
                    else:
                        err_msg = "Wrong tag"
                    info.fail(err_msg, data)
                case (True, TestType.INVALID):
                    # TODO: think of a message for this case.
                    info.fail(None, data)
                case (False, TestType.INVALID):
                    # FIXME: testing should use the flags/comments and check if the
                    # expected behaviour is triggered or another error is used.
                    info.ok(data)
                case (True, TestType.ACCEPTABLE):
                    info.ok(data)
                case (False, TestType.ACCEPTABLE):
                    # TODO: add a message?
                    info.fail(data=data)
                case _:
                    # Catch-all in case shenanigans happen.
                    raise ValueError(
                        f"Unexpected result: {is_same_ct = }, {is_same_tag = }, {test.type = }"  # noqa: E501
                    )
            results.add(info)

    return rd


def test_decrypt(
    decrypt: Decrypt,
    mode: Mode,
    keylen: KeyLength,
    *,
    compliance: bool = True,
    resilience: bool = False,
) -> ResultsDict:
    """Tests a function that decrypt with AES.

    Args:
        decrypt: The function to test.
        mode: The AES mode implemented. To more different modes, make separate calls to
            this function.
        keylen: The length of the keys to use.

    Keyword Args:
        compliance: Whether to use compliance test vectors.
        resilience: Whether to use resilience test vectors.

    Returns:
        A dictionary of results.

    Example:
        Let's test PyCryptodome with AES-256-GCM.

        We start by importing the AES module.

        >>> from crypto_condor.primitives import AES

        We need to wrap the encryption to match the signature of :protocol:`Decrypt`.

        >>> from Crypto.Cipher import AES as pycAES

        >>> def aes_gcm(
        ...     key: bytes,
        ...     ciphertext: bytes,
        ...     *,
        ...     iv: bytes | None = None,
        ...     aad: bytes | None = None,
        ...     mac: bytes | None = None,
        ...     mac_len: int = 0,
        ... ) -> AES.CiphertextAndTag:
        ...     cipher = pycAES.new(key, pycAES.MODE_GCM, nonce=iv, mac_len=mac_len)
        ...     if aad is not None:
        ...         cipher.update(aad)
        ...     try:
        ...         pt = cipher.decrypt_and_verify(ciphertext, mac)
        ...         return (pt, True)
        ...     except ValueError:
        ...         return (None, False)

        We define the parameters to test using the corresponding enums. We can use them
        directly but this simplifies the function call.

        >>> mode, keylen = AES.Mode.GCM, AES.KeyLength.AES256

        And now, we test the function.

        >>> res = AES.test_decrypt(aes_gcm, mode, keylen)
        [GCM][256][NIST CAVP] Testing decryption ...
        >>> assert res.check()
    """
    all_vectors = _load_vectors(mode, keylen)
    rd = ResultsDict()

    test: AesTest
    for vectors in all_vectors:
        if not vectors.decrypt:
            continue
        if not compliance and vectors.compliance:
            continue
        if not resilience and not vectors.compliance:
            continue

        results = Results.new(f"Tests AES-{mode} decryption", ["mode", "keylen"])
        rd.add(
            results,
            ["mode"],
            extra_values=[str(vectors.keylen), vectors.source.replace(" ", "_")],
        )

        for test in track(
            vectors.tests,
            rf"\[{mode}]\[{keylen}]\[{vectors.source}] Testing decryption",
        ):
            info = TestInfo.new_from_test(test, vectors.compliance)
            data = DecData(test.key, test.ct, test.pt, test.iv, test.aad, test.tag)

            try:
                ret_pt, ret_valid_tag = _try_one_dec(decrypt, mode, test)
            except Exception as error:
                if test.type == "invalid":
                    # FIXME: overly permissive
                    info.ok(data)
                else:
                    info.fail(f"Exception raised: {str(error)}", data)
                results.add(info)
                continue

            # Add returned values to debug data.
            data.ret_pt = ret_pt
            data.ret_valid_tag = ret_valid_tag

            # In all modes, check if plaintext matches.
            is_same_pt = ret_pt == test.pt

            # Check if tag is considered valid only for AEAD modes.
            if mode in Mode.classic_modes():
                is_valid_tag = True
            elif ret_valid_tag is None:
                # For AEAD modes, the second returned value must be a bool.
                info.fail(
                    "Second returned value is None, missing tag verification status",
                    data,
                )
                results.add(info)
                continue
            else:
                is_valid_tag = ret_valid_tag

            match (test.type, is_same_pt and is_valid_tag, mode):
                case (TestType.VALID, True, _):
                    info.ok(data)
                case (TestType.VALID, False, Mode.CCM | Mode.GCM):
                    if not is_valid_tag:
                        err_msg = "Tag considered invalid"
                    if not is_same_pt:
                        err_msg = "Wrong plaintext"
                    info.fail(err_msg, data)
                case (TestType.VALID, False, _):
                    info.fail("Wrong plaintext", data)
                case (TestType.INVALID, True, Mode.CCM | Mode.GCM):
                    # FIXME: use flags/comments to check if expected behaviour is
                    # triggered or if it's another error.
                    info.fail("Invalid plaintext/tag accepted", data)
                case (TestType.INVALID, True, _):
                    info.fail("Wrong plaintext")
                case (TestType.INVALID, False, _):
                    # FIXME: overly permissive.
                    info.ok(data)
                case (TestType.ACCEPTABLE, True, _):
                    info.ok(data)
                case (TestType.ACCEPTABLE, False, _):
                    # TODO: add a message.
                    info.fail(None, data)
                case _:
                    # Catch-all in case shenanigans happen.
                    raise ValueError(
                        f"Unexpected result: {is_same_pt = }, {is_valid_tag = }, {test.type = }"  # noqa: E501
                    )
            results.add(info)

    return rd


def _test_output_enc(line: str, mode: Mode):
    match line.rstrip().split("/"):
        case [_k, _p, _c]:
            if mode != Mode.ECB:
                raise ParsingError("Got 3 values but the mode is not ECB")
            key, pt, ct = map(bytes.fromhex, (_k, _p, _c))
            ref_ct = _encrypt(mode, key, pt)
            return EncData(key, pt, ct, None, None, None, ref_ct, None)
        case [_k, _p, _c, _i]:
            if mode == Mode.ECB or mode == Mode.CCM or mode == Mode.GCM:
                raise ParsingError(f"Got 4 values but the mode is {str(mode)}")
            key, pt, ct, iv = map(bytes.fromhex, (_k, _p, _c, _i))
            ref_ct = _encrypt(mode, key, pt, iv=iv)
            return EncData(key, pt, ct, iv, None, None, ref_ct, None)
        case [_k, _p, _c, _i, _a, _t]:
            if mode != Mode.CCM and mode != Mode.GCM:
                raise ParsingError("Got 6 values but the mode is not GCM or CCM")
            key, pt, ct, iv, aad, tag = map(bytes.fromhex, (_k, _p, _c, _i, _a, _t))
            ref_ct, ref_tag = _encrypt(mode, key, pt, iv=iv, aad=aad, mac_len=len(tag))
            return EncData(key, pt, ct, iv, aad, tag, ref_ct, ref_tag)
        case _:
            raise ParsingError(
                f"Got {len(line.split('/'))} values, expected 3, 4, or 6"
            )


def test_output_encrypt(filename: str, mode: Mode) -> ResultsDict:
    r"""Tests the output of an implementation of AES encryption.

    .. attention::

        This function uses the internal implementation of AES, which must be compiled
        and installed locally. This is done automatically when the function is called
        for the first time. If the installation fails, this function will not work.

    Format:
        - One set of arguments per line.
        - Lines are separated by newlines ``\n``.
        - Lines that start with ``#`` are counted as comments and ignored.
        - Arguments are written in hexadecimal and separated by forward slashes.
        - For ECB, the order is:

        .. code::

            key/plaintext/ciphertext

        - For other classic modes of operation (CBC, CTR, CFB) the order is:

        .. code::

            key/plaintext/ciphertext/iv

        - For AEAD modes (CCM, GCM) the order is:

        .. code::

            key/plaintext/ciphertext/iv/[aad]/[mac]

        - Where:
            - ``key`` is the key used.
            - ``plaintext`` is the input message.
            - ``ciphertext`` is the result of the operation.
            - ``iv`` is the IV or nonce used for that operation.
            - ``aad`` is the associated data. It is optional and can be empty. Even if
              not used, the corresponding slashes must be present.
            - ``mac`` is the MAC tag generated when encrypting.

    Args:
        filename:
            The name of the file to test.
        mode:
            The mode of operation used.

    Returns:
        A dictionary of Results, containing a single instance.
    """
    in_file = Path(filename)
    if not in_file.is_file():
        raise FileNotFoundError(f"Can't find file {filename}")

    with in_file.open("r") as file:
        lines = file.readlines()
    res = Results.new(
        "Tests the output of implementation of AES encryption.", ["filename", "mode"]
    )

    tid = 0
    for line_number, line in track(enumerate(lines, start=1), "Testing file"):
        if line.startswith("#"):
            continue
        tid += 1
        info = TestInfo.new(tid, TestType.VALID, ["UserInput"], f"Line {line_number}")

        try:
            data = _test_output_enc(line, mode)
        except ValueError as error:
            info.fail(f"Caught ValueError: {str(error)}")
            res.add(info)
            continue
        except ParsingError as error:
            info.fail(f"Failed to parse line {line_number}: {str(error)}")
            res.add(info)
            continue

        if mode in Mode.classic_modes():
            if data.ret_ct == data.ct:
                info.ok(data)
            else:
                info.fail("Wrong ciphertext", data)
        else:
            if data.ret_ct != data.ct and data.ret_tag != data.tag:
                info.fail("Wrong ciphertext and tag", data)
            elif data.ret_ct != data.ct:
                info.fail("Wrong ciphertext", data)
            elif data.ret_tag != data.tag:
                info.fail("Wrong tag", data)
            else:
                info.ok(data)
        res.add(info)

    rd = ResultsDict()
    rd.add(res)
    return rd


def _test_output_dec(line: str, mode: Mode):
    match line.rstrip().split("/"):
        case [_k, _c, _p]:
            if mode != Mode.ECB:
                raise ParsingError("Got 3 values but the mode is not ECB")
            key, ct, pt = map(bytes.fromhex, (_k, _c, _p))
            ref_pt = _decrypt(mode, key, ct)
            return DecData(key, ct, pt, None, None, None, ref_pt, None)
        case [_k, _c, _p, _i]:
            if mode == Mode.ECB or mode == Mode.CCM or mode == Mode.GCM:
                raise ParsingError(f"Got 4 values but the mode is {str(mode)}")
            key, ct, pt, iv = map(bytes.fromhex, (_k, _c, _p, _i))
            ref_pt = _decrypt(mode, key, ct, iv=iv)
            return DecData(key, ct, pt, iv, None, None, ref_pt, None)
        case [_k, _c, _p, _i, _a, _t]:
            if mode != Mode.CCM and mode != Mode.GCM:
                raise ParsingError("Got 6 values but the mode is not GCM or CCM")
            key, ct, pt, iv, aad, tag = map(bytes.fromhex, (_k, _c, _p, _i, _a, _t))
            ref_pt_aead, ref_status = _decrypt(
                mode, key, ct, iv=iv, aad=aad, mac=tag, mac_len=len(tag)
            )
            return DecData(key, ct, pt, iv, aad, tag, ref_pt_aead, ref_status)
        case _:
            raise ParsingError(
                f"Got {len(line.split('/'))} values, expected 3, 4, or 6"
            )


def test_output_decrypt(filename: str, mode: Mode) -> ResultsDict:
    r"""Tests the output of an implementation of AES decryption.

    .. attention::

        This function uses the internal implementation of AES, which must be compiled
        and installed locally. This is done automatically when the function is called
        for the first time. If the installation fails, this function will not work.

    Format:
        - One set of arguments per line.
        - Lines are separated by newlines ``\n``.
        - Lines that start with ``#`` are counted as comments and ignored.
        - Arguments are written in hexadecimal and separated by forward slashes.
        - For ECB, the order is:

        .. code::

            key/ciphertext/plaintext

        - For other classic modes of operation (CBC, CTR, CFB) the order is:

        .. code::

            key/ciphertext/plaintext/iv

        - For AEAD modes (CCM, GCM) the order is:

        .. code::

            key/ciphertext/plaintext/iv/[aad]/[mac]

        - Where:
            - ``key`` is the key used.
            - ``ciphertext`` is the input message.
            - ``plaintext`` is the result of the operation.
            - ``iv`` is the IV or nonce used for that operation.
            - ``aad`` is the associated data. It is optional and can be empty. Even if
              not used, the corresponding slashes must be present.
            - ``mac`` is the MAC tag generated when encrypting.

    Args:
        filename:
            The name of the file to test.
        mode:
            The mode of operation used.

    Returns:
        A dictionary of Results, containing a single instance.
    """
    in_file = Path(filename)
    if not in_file.is_file():
        raise FileNotFoundError(f"Can't find file {filename}")

    with in_file.open("r") as file:
        lines = file.readlines()
    res = Results.new(
        "Tests the output of implementation of AES decryption.", ["filename", "mode"]
    )

    tid = 0
    for line_number, line in track(enumerate(lines, start=1), "Testing file"):
        if line.startswith("#"):
            continue
        tid += 1
        info = TestInfo.new(tid, TestType.VALID, ["UserInput"], f"Line {line_number}")

        try:
            data = _test_output_dec(line, mode)
        except ValueError as error:
            info.fail(f"Caught ValueError: {str(error)}")
            res.add(info)
            continue
        except ParsingError as error:
            info.fail(f"Failed to parse line {line_number}: {str(error)}")
            res.add(info)
            continue

        if mode in Mode.classic_modes():
            if data.ret_pt == data.pt:
                info.ok(data)
            else:
                info.fail("Wrong plaintext", data)
        else:
            if not data.ret_valid_tag:
                info.fail("Tag verification failed", data)
            elif data.ret_pt != data.pt:
                info.fail("Wrong plaintext", data)
            else:
                info.ok(data)
        res.add(info)

    rd = ResultsDict()
    rd.add(res)
    return rd


def test(
    encrypt: Encrypt | None,
    decrypt: Decrypt | None,
    mode: Mode,
    key_length: KeyLength,
    *,
    compliance: bool = True,
    resilience: bool = False,
) -> ResultsDict:
    """Tests implementations of AES encryption and decryption.

    Args:
        encrypt: The encryption function to test.
        decrypt: The decryption function to test.
        mode: The mode of operation.
        key_length: The key sizes to use.

    Keyword Args:
        compliance: Whether to use compliance test vectors.
        resilience: Whether to use resilience test vectors.

    Returns:
        A dictionary of results.

    .. deprecated:: TODO(version)
        Use :func:`test_encrypt` and :func:`test_decrypt` instead.
    """
    rd = ResultsDict()
    if not compliance and not resilience:
        return rd
    if encrypt is not None:
        rd |= test_encrypt(
            encrypt, mode, key_length, compliance=compliance, resilience=resilience
        )
    if decrypt is not None:
        rd |= test_decrypt(
            decrypt, mode, key_length, compliance=compliance, resilience=resilience
        )
    return rd


def verify_file(filename: str, mode: Mode, operation: Operation) -> ResultsDict:
    r"""Tests the output of an implementation.

    Format:
        - One set of arguments per line.
        - Lines are separated by newlines ``\n``.
        - Lines that start with ``#`` are counted as comments and ignored.
        - Arguments are written in hexadecimal and separated by forward slashes.
        - For ECB, the order is:

        .. code::

            key/plaintext/ciphertext

        - For other classic modes of operation (CBC, CTR, CFB) the order is:

        .. code::

            key/plaintext/ciphertext/iv

        - For AEAD modes (CCM, GCM) the order is:

        .. code::

            key/plaintext/ciphertext/iv/[aad]/[mac]

        - Where:
            - ``key`` is the key used.
            - ``plaintext`` is the input message.
            - ``ciphertext`` is the result of the operation.
            - ``iv`` is the IV or nonce used for that operation.
            - ``aad`` is the associated data. It is optional and can be empty. Even if
              not used, the corresponding slashes must be present.
            - ``mac`` is the MAC tag generated when encrypting.

    Args:
        filename: The name of the file to test.
        mode: The mode of operation used to generate the file.
        operation: The operation used.

    Returns:
        A dictionary of results.

    .. deprecated:: TODO(version)
        Use :func:`test_output_encrypt` and :func:`test_output_decrypt` instead.
    """
    if operation == Operation.ENCRYPT:
        return test_output_encrypt(filename, mode)
    else:
        return test_output_decrypt(filename, mode)


# --------------------------- Runners -------------------------------------------------


def run_python_wrapper(
    wrapper: Path, compliance: bool, resilience: bool
) -> ResultsDict:
    """Runs an AES Python wrapper.

    See :doc:`AES wrapper </wrapper-api/AES>` for a description of the wrappers.

    Args:
        wrapper: A path to the wrapper to run. Must be a Python program.
        compliance: Whether to use compliance test vectors.
        resilience: Whether to use resilience test vectors.

    Returns:
        A dictionary of results.
    """
    logger.info("Running Python AES wrapper: '%s'", str(wrapper.name))
    sys.path.insert(0, str(wrapper.parent.absolute()))
    already_imported = wrapper.stem in sys.modules.keys()
    try:
        aes_wrapper = importlib.import_module(wrapper.stem)
    except ModuleNotFoundError as error:
        logger.error("Can't import wrapper: '%s'", str(error))
        raise
    if already_imported:
        logger.debug("Reloading AES wrapper: '%s'", wrapper.stem)
        aes_wrapper = importlib.reload(aes_wrapper)

    rd = ResultsDict()

    for symbol in dir(aes_wrapper):
        match symbol.split("_"):
            case ["CC", "AES", _mode, ("encrypt" | "decrypt") as op]:
                logger.info("Found CC_AES function %s", symbol)
                try:
                    mode = Mode(_mode)
                except ValueError:
                    logger.error("Unknown mode %s for AES", _mode)
                    continue
                if op == "encrypt":
                    rd |= test_encrypt(
                        getattr(aes_wrapper, symbol),
                        mode,
                        KeyLength.ALL,
                        compliance=compliance,
                        resilience=resilience,
                    )
                else:
                    rd |= test_decrypt(
                        getattr(aes_wrapper, symbol),
                        mode,
                        KeyLength.ALL,
                        compliance=compliance,
                        resilience=resilience,
                    )
            case ["CC", "AES", _mode, _klen, ("encrypt" | "decrypt") as op]:
                logger.info("Found CC_AES function %s", symbol)
                try:
                    mode = Mode(_mode)
                    klen = KeyLength(int(_klen))
                except ValueError as error:
                    logger.error(
                        "Invalid parameter '%s', skip function %s", str(error), symbol
                    )
                    continue
                if op == "encrypt":
                    rd |= test_encrypt(
                        getattr(aes_wrapper, symbol),
                        mode,
                        klen,
                        compliance=compliance,
                        resilience=resilience,
                    )
                else:
                    rd |= test_decrypt(
                        getattr(aes_wrapper, symbol),
                        mode,
                        klen,
                        compliance=compliance,
                        resilience=resilience,
                    )
            case ["CC", "AES", *_]:
                logger.warning("Ignored unknown CC_AES symbol %s", symbol)
            case _:
                pass

    return rd


# --------------------------- Lib hook functions --------------------------------------


def _test_lib_enc(
    ffi: cffi.FFI,
    lib,
    function: str,
    mode: Mode,
    key_length: KeyLength,
    compliance: bool,
    resilience: bool,
) -> ResultsDict:
    """Tests CC_AES_encrypt.

    Returns:
        The dictionary of results returned by :func:`test_encrypt`.
    """
    logger.info("Testing harness function %s", function)

    ffi.cdef(
        f"""int {function}(uint8_t *ciphertext, size_t ciphertext_size,
                const uint8_t *plaintext, size_t plaintext_size,
                const uint8_t *key, size_t key_size,
                const uint8_t *iv, size_t iv_size);"""
    )
    enc = getattr(lib, function)

    def _enc(key: bytes, plaintext: bytes, iv: bytes = b"") -> bytes:
        c_key = ffi.new("uint8_t[]", key)
        c_pt = ffi.new("uint8_t[]", plaintext)
        c_iv = ffi.new("uint8_t[]", iv)
        if mode == Mode.CBC_PKCS7:
            pad_len = 16 - (len(plaintext) % 16)
            ct_len = len(plaintext) + pad_len
            c_ct = ffi.new(f"uint8_t[{ct_len}]")
        else:
            # ct_len = ((len(plaintext) + 15) // 16) * 16
            ct_len = len(plaintext)
            c_ct = ffi.new(f"uint8_t[{ct_len}]")
        rc = enc(c_ct, ct_len, c_pt, len(plaintext), c_key, len(key), c_iv, len(iv))
        if rc == 1:
            return bytes(c_ct)
        else:
            raise ValueError(f"Encrypt function failed with code {rc}")

    return test_encrypt(
        _enc,  # type: ignore[arg-type]
        mode,
        key_length,
        compliance=compliance,
        resilience=resilience,
    )


def _test_lib_dec(
    ffi: cffi.FFI,
    lib,
    function: str,
    mode: Mode,
    key_length: KeyLength,
    compliance: bool,
    resilience: bool,
) -> ResultsDict:
    """Tests CC_AES_decrypt.

    Returns:
        The dictionary of results returned by :func:`test_decrypt`.
    """
    logger.info("Testing harness function %s", function)

    ffi.cdef(
        f"""int {function}(uint8_t *plaintext, size_t plaintext_size,
                const uint8_t *ciphertext, size_t ciphertext_size,
                const uint8_t *key, size_t key_size,
                const uint8_t *iv, size_t iv_size);"""
    )
    dec = getattr(lib, function)

    def _dec(key: bytes, ciphertext: bytes, iv: bytes = b"") -> bytes:
        c_key = ffi.new("uint8_t[]", key)
        c_ct = ffi.new("uint8_t[]", ciphertext)
        c_iv = ffi.new("uint8_t[]", iv)
        c_pt = ffi.new(f"uint8_t[{len(ciphertext)}]")
        rc = dec(
            c_pt, len(ciphertext), c_ct, len(ciphertext), c_key, len(key), c_iv, len(iv)
        )
        if rc == 1:
            return bytes(c_pt)
        else:
            raise ValueError(f"Decrypt failed with code {rc}")

    return test_decrypt(
        _dec,  # type: ignore[arg-type]
        mode,
        key_length,
        compliance=compliance,
        resilience=resilience,
    )


def _test_lib_enc_aead(
    ffi: cffi.FFI,
    lib,
    function: str,
    mode: Mode,
    key_length: KeyLength,
    compliance: bool,
    resilience: bool,
) -> ResultsDict:
    """Tests CC_AES_AEAD_encrypt.

    Returns:
        The dictionary of results returned by :func:`test`.
    """
    logger.info("Testing harness function %s", function)

    ffi.cdef(
        f"""int {function}(uint8_t *ciphertext, size_t ciphertext_size,
                uint8_t *mac, size_t mac_size,
                const uint8_t *plaintext, size_t plaintext_size,
                const uint8_t *key, size_t key_size,
                const uint8_t *nonce, size_t nonce_size,
                const uint8_t *aad, size_t aad_size);"""
    )
    enc = getattr(lib, function)

    def _enc(
        key: bytes, plaintext: bytes, iv: bytes, aad: bytes, mac_len: int
    ) -> CiphertextAndTag:
        c_key = ffi.new("uint8_t[]", key)
        c_pt = ffi.new("uint8_t[]", plaintext)
        c_ct = ffi.new(f"uint8_t[{len(plaintext)}]")
        c_iv = ffi.new("uint8_t[]", iv)
        c_mac = ffi.new(f"uint8_t[{mac_len}]")

        c_aad: Any
        if aad:
            aad_len = len(aad)
            c_aad = ffi.new("uint8_t[]", aad)
        else:
            aad_len = 0
            c_aad = ffi.NULL

        rc = enc(
            c_ct,
            len(plaintext),
            c_mac,
            mac_len,
            c_pt,
            len(plaintext),
            c_key,
            len(key),
            c_iv,
            len(iv),
            c_aad,
            aad_len,
        )
        if rc == 1:
            return bytes(c_ct), bytes(c_mac)
        else:
            raise ValueError(f"Encrypt failed with code {rc}")

    return test_encrypt(
        _enc,  # type: ignore[arg-type]
        mode,
        key_length,
        compliance=compliance,
        resilience=resilience,
    )


def _test_lib_dec_aead(
    ffi: cffi.FFI,
    lib,
    function: str,
    mode: Mode,
    key_length: KeyLength,
    compliance: bool,
    resilience: bool,
) -> ResultsDict:
    """Tests CC_AES_AEAD_decrypt.

    Returns:
        The dictionary of results returned by :func:`test`.
    """
    logger.info("Testing harness function %s", function)

    ffi.cdef(
        f"""int {function}(uint8_t *plaintext, size_t plaintext_size,
                const uint8_t *ciphertext, size_t ciphertext_size,
                const uint8_t *mac, size_t mac_size,
                const uint8_t *key, size_t key_size,
                const uint8_t *iv, size_t iv_size,
                const uint8_t *aad, size_t aad_size);"""
    )
    dec = getattr(lib, function)

    def _dec(
        key: bytes, ciphertext: bytes, iv: bytes, aad: bytes, mac: bytes, mac_len: int
    ) -> PlaintextAndBool:
        c_key = ffi.new("uint8_t[]", key)
        c_ct = ffi.new("uint8_t[]", ciphertext)
        c_pt = ffi.new(f"uint8_t[{len(ciphertext)}]")
        c_iv = ffi.new("uint8_t[]", iv)
        c_mac = ffi.new("uint8_t[]", mac)

        c_aad: Any
        if aad:
            aad_len = len(aad)
            c_aad = ffi.new(f"uint8_t[{aad_len}]", aad)
        else:
            aad_len = 0
            c_aad = ffi.NULL

        rc = dec(
            c_pt,
            len(ciphertext),
            c_ct,
            len(ciphertext),
            c_mac,
            mac_len,
            c_key,
            len(key),
            c_iv,
            len(iv),
            c_aad,
            aad_len,
        )
        if rc == 1:
            return (bytes(c_pt), True)
        elif rc == -1:
            return (None, False)
        else:
            raise ValueError(f"Decrypt failed with code {rc}")

    return test_decrypt(
        _dec,  # type: ignore[arg-type]
        mode,
        key_length,
        compliance=compliance,
        resilience=resilience,
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
            A list of CC_AES functions to test.
        compliance:
            Whether to use compliance test vectors.
        resilience:
            Whether to use resilience test vectors.
    """
    logger.info("Found harness functions %s", ", ".join(functions))

    results = ResultsDict()

    # First pattern matching to parse both possible conventions (with or without key
    # size), interpreting the parameters if possible, skipping if not.
    # Second pattern matching to call the correct function depending on mode (classic
    # vs. AEAD) and operation.
    # CBC-PKCS7 is a special case as we would replace the hyphen in its name by an
    # underscore, which would add more cases. So instead we use CBCPKCS7 and take this
    # into account before passing the string to Mode.
    for function in functions:
        match function.split("_"):
            case ["CC", "AES", _mode, ("encrypt" | "decrypt") as op]:
                logger.info("Found CC_AES function %s", function)
                try:
                    mode = Mode.CBC_PKCS7 if _mode == "CBCPKCS7" else Mode(_mode)
                except ValueError as error:
                    logger.error(
                        "Invalid parameter '%s', skip function %s", str(error), function
                    )
                    continue
                klen = KeyLength.ALL
            case ["CC", "AES", _mode, _klen, ("encrypt" | "decrypt") as op]:
                logger.info("Found CC_AES function %s", function)
                try:
                    mode = Mode.CBC_PKCS7 if _mode == "CBCPKCS7" else Mode(_mode)
                    klen = KeyLength(int(_klen))
                except ValueError as error:
                    logger.error(
                        "Invalid parameter '%s', skip function %s", str(error), function
                    )
                    continue
            case ["CC", "AES", *_]:
                logger.warning("Ignored unknown CC_AES function '%s'", function)
                continue
            case _:
                continue

        # If the condition is false, it continues searching for a pattern.
        match (mode, op):
            case (mode, "encrypt") if mode in Mode.classic_modes():
                results |= _test_lib_enc(
                    ffi, lib, function, mode, klen, compliance, resilience
                )
            case (mode, "encrypt"):
                results |= _test_lib_enc_aead(
                    ffi, lib, function, mode, klen, compliance, resilience
                )
            case (mode, "decrypt") if mode in Mode.classic_modes():
                results |= _test_lib_dec(
                    ffi, lib, function, mode, klen, compliance, resilience
                )
            case (mode, "decrypt"):
                results |= _test_lib_dec_aead(
                    ffi, lib, function, mode, klen, compliance, resilience
                )

    return results


if __name__ == "__main__":
    # Calling this module as a script installs the AES binary manually.
    _ = _get_aes_lib()
