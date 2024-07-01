"""Module to test AES implementations.

The :mod:`crypto_condor.primitives.AES` module can test implementations of `AES
</method/AES>` encryption and decryption using several modes of operations with the
:func:`test` function. Supported modes are defined by the :enum:`Mode` enum.
"""

from __future__ import annotations

import importlib
import logging
import subprocess
import sys
import zipfile
import zlib
from importlib import resources
from pathlib import Path
from typing import TYPE_CHECKING, Literal, Protocol, overload

import attrs
import cffi
import strenum
from Crypto.Cipher import AES as pycryptoAES
from Crypto.Util import Padding
from rich.progress import track

from crypto_condor.primitives.common import (
    CiphertextAndTag,
    DebugInfo,
    PlaintextAndBool,
    Results,
    ResultsDict,
    TestType,
    get_appdata_dir,
)
from crypto_condor.vectors.AES import AesVectors, KeyLength, Mode

if TYPE_CHECKING:
    import _cffi_backend

logger = logging.getLogger(__name__)


def __dir__():  # pragma: no cover
    return [
        # Enums
        Wrapper.__name__,
        Operation.__name__,
        # Protocols
        Encrypt.__name__,
        Decrypt.__name__,
        # Dataclasses
        # Test functions
        run_wrapper.__name__,
        test.__name__,
        verify_file.__name__,
        # Imported
        KeyLength.__name__,
        Mode.__name__,
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
    C = "C"


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
class AesData:
    """Debug data for AES tests.

    Args:
        info: Common debug info, see :class:`crypto_condor.primitives.common.DebugInfo`.
        operation: The operation performed, see :enum:`Operation`.
        key: The symmetric key used.
        message: The message to encrypt or decrypt.
        expected: The expected plaintext or ciphertext.
        result: The actual plaintext or ciphertext. Can be None if the operation failed.
        iv: The IV or nonce used by most modes of operation. Use None if there is no IV.
        aad: The associated data for AEAD modes, None if there is no associated data.
        mac: The MAC tag used by AEAD modes. Use None if there is no MAC tag.
        expected_mac: The expected MAC when encrypting with AEAD modes. Use None if
            there is no MAC tag.
        valid_mac: Whether the received MAC is valid for a given set of inputs. Use None
            if the tag is not being verified (the mode is not AEAD or the operation is
            encryption).
    """

    info: DebugInfo
    operation: Operation
    key: bytes
    message: bytes
    expected: bytes | None
    result: bytes | None = None
    iv: bytes | None = None
    aad: bytes | None = None
    expected_mac: bytes | None = None
    mac: bytes | None = None
    valid_mac: bool | None = None

    def __str__(self) -> str:
        """Returns a string representation of the present fields."""
        s = str(self.info)

        s += f"Operation: {self.operation}\n"
        s += f"key = {self.key.hex()}\n"
        s += f"message = {self.message.hex() if self.message else '<empty>'}\n"
        s += f"expected = {self.expected.hex() if self.expected else '<empty>'}\n"

        # If no tag verification or valid MAC, try to print the result, otherwise if the
        # MAC is invalid don't release the plaintext even if it was returned.
        if self.valid_mac is None or self.valid_mac:
            s += f"result = {self.result.hex() if self.result else '<empty>'}\n"
        else:
            s += "result = <decryption error>\n"

        if self.iv is not None:
            s += f"iv/nonce = {self.iv.hex() if self.iv else '<empty>'}\n"
        if self.aad is not None:
            s += f"aad = {self.aad.hex() if self.aad else '<empty>'}\n"
        if self.mac is not None:
            s += f"tag = {self.mac.hex() if self.mac else '<empty>'}\n"
        if self.expected_mac is not None:
            et = f"{self.expected_mac.hex() if self.expected_mac else '<empty>'}"
            s += f"expected tag = {et}\n"
        if self.valid_mac is not None:
            s += f"MAC is valid = {'TRUE' if self.valid_mac else 'FALSE'}\n"

        return s


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


def _run_python(
    wrapper: Path,
    mode: Mode,
    key_length: KeyLength,
    compliance: bool,
    resilience: bool,
    encrypt: bool,
    decrypt: bool,
    iv_length: int,
) -> ResultsDict:
    """Runs the Python AES wrapper.

    Args:
        wrapper: The Python wrapper to test.
        mode: The mode of operation to test.
        key_length: The length of the keys to use, in bits. Use 0 to test all lengths.
        compliance: Whether to run compliance test vectors.
        resilience: Whether to run resilience test vectors.
        encrypt: Whether to test the encryption.
        decrypt: Whether to test the decryption.
        iv_length: The length of the IV to test. If 0, use any test vector available.

    Raises:
        FileNotFoundError: If the wrapper couldn't be found or imported.
    """
    logger.info("Running Python AES wrapper")
    sys.path.insert(0, str(wrapper.parent.absolute()))
    already_imported = wrapper.stem in sys.modules.keys()
    try:
        aes_wrapper = importlib.import_module(wrapper.stem)
    except ModuleNotFoundError as error:
        logger.error("Can't import wrapper: %s", str(error))
        raise
    if already_imported:
        logger.debug("Reloading AES wrapper module %s", wrapper.stem)
        aes_wrapper = importlib.reload(aes_wrapper)
    encrypt_function = aes_wrapper.encrypt if encrypt else None
    decrypt_function = aes_wrapper.decrypt if decrypt else None
    result_dict = test(
        encrypt_function,
        decrypt_function,
        mode,
        key_length,
        iv_length=iv_length,
        compliance=compliance,
        resilience=resilience,
    )
    return result_dict


def _run_c(
    wrapper: Path,
    mode: Mode,
    key_length: KeyLength,
    compliance: bool,
    resilience: bool,
    encrypt: bool,
    decrypt: bool,
    iv_length: int,
) -> ResultsDict:
    """Runs the C AES wrapper.

    Args:
        wrapper: The executable C wrapper to test.
        mode: The mode of operation to test.
        key_length: The length of the keys to use, in bits. Use 0 to test all lengths.
        compliance: Whether to run compliance test vectors.
        resilience: Whether to run resilience test vectors.
        encrypt: Whether to test the encryption.
        decrypt: Whether to test the decryption.
        iv_length: The length of the IV to test. If 0, use any test vector available.

    Raises:
        FileNotFoundError: If the wrapper couldn't be found or imported.
    """
    exe = wrapper.absolute()

    def enc(
        key: bytes,
        plaintext: bytes,
        *,
        iv: bytes | None = None,
        segment_size: int = 0,
        aad: bytes | None = None,
        mac_len: int = 0,
    ) -> bytes | CiphertextAndTag:
        """Function for encryption.

        See :func:`~crypto_condor.primitives.AES._encrypt`.
        """
        args = [str(exe)]
        args += ["--key", key.hex()]
        args += ["--text", plaintext.hex()]
        if iv is not None:
            args += ["--iv", iv.hex()]
        if aad is not None:
            args += ["--aad", aad.hex() if aad else ""]
        if mac_len > 0:
            args += ["--tag-length", str(mac_len)]
        if segment_size > 0:
            args += ["--segment-size", str(segment_size)]
        if mode not in Mode.classic_modes():
            args += ["--mode", "1"]
        result = subprocess.run(args, capture_output=True, text=True)
        if result.returncode != 0:
            raise ValueError(result.stdout)

        if mode in Mode.classic_modes():
            ct = bytes.fromhex(result.stdout.strip())
            return ct
        else:
            # remove trailing whitespace
            out = result.stdout.rstrip()
            # separate the two lines of output
            lines = out.split("\n")
            # get the ciphertext
            if len(lines[0].split(" = ")) == 1:
                c = ""
            else:
                _, c = lines[0].split(" = ")
            # get the tag
            _, t = lines[1].split(" = ")
            return (bytes.fromhex(c), bytes.fromhex(t))

    def dec(
        key: bytes,
        ciphertext: bytes,
        *,
        iv: bytes | None = None,
        aad: bytes | None = None,
        mac: bytes | None = None,
        mac_len: int = 0,
        segment_size: int = 0,
    ) -> bytes | PlaintextAndBool:
        """Function for decryption.

        See :func:`~crypto_condor.primitives.AES._decrypt`.
        """
        args = [str(exe)]
        args += ["--key", key.hex()]
        args += ["--text", ciphertext.hex()]
        args += ["--decrypt"]
        if iv is not None:
            args += ["--iv", iv.hex()]
        if aad is not None:
            args += ["--aad", aad.hex() if aad else ""]
        if mac is not None:
            args += ["--tag", mac.hex() if mac else ""]
        if segment_size > 0:
            args += ["--segment-size", str(segment_size)]
        if mode not in Mode.classic_modes():
            args += ["--mode", "1"]
        result = subprocess.run(args, capture_output=True, text=True)
        if result.returncode != 0:
            raise ValueError(result.stdout)

        if mode in Mode.classic_modes():
            pt = bytes.fromhex(result.stdout.strip())
            return pt
        else:
            # strip the trailing newline
            out = result.stdout.rstrip()
            # separate the two output lines
            lines = out.split("\n")
            # check the tag verification
            _, v = lines[0].split(" = ")
            if v == "FAIL":
                return (None, False)
            # get the message
            _, p = lines[1].split(" = ")
            return (bytes.fromhex(p), True)

    encrypt_function = enc if encrypt else None
    decrypt_function = dec if decrypt else None
    # TODO: fix type error by defining encrypt/decrypt depending on the mode of
    # operation.
    result_group = test(
        encrypt_function,  # type: ignore
        decrypt_function,  # type: ignore
        mode,
        key_length,
        compliance=compliance,
        resilience=resilience,
        iv_length=iv_length,
    )
    return result_group


def run_wrapper(
    wrapper: Path,
    mode: Mode,
    key_length: KeyLength = KeyLength.ALL,
    *,
    compliance: bool = True,
    resilience: bool = True,
    encrypt: bool = True,
    decrypt: bool = True,
    iv_length: int = 0,
):
    """Runs a wrapper.

    Args:
        wrapper: The wrapper to test.
        mode: The mode of operation to test.
        key_length: The length of the keys to use, in bits.

    Keyword Args:
        compliance: Whether to run compliance test vectors.
        resilience: Whether to run resilience test vectors.
        encrypt: Whether to test the encryption.
        decrypt: Whether to test the decryption.
        iv_length: The length of the IV to test. If 0, use any test vector available.

    Returns:
        Returns the results from :func:`test`.
    """
    if not wrapper.is_file():
        raise FileNotFoundError(f"AES wrapper not found: {str(wrapper)}")
    if wrapper.suffix == ".py":
        return _run_python(
            wrapper,
            mode,
            key_length,
            compliance,
            resilience,
            encrypt,
            decrypt,
            iv_length,
        )
    else:
        return _run_c(
            wrapper,
            mode,
            key_length,
            compliance,
            resilience,
            encrypt,
            decrypt,
            iv_length,
        )


def _test_nist_encrypt(
    encrypt: Encrypt, mode: Mode, key_length: KeyLength
) -> ResultsDict:
    """Tests encryption using NIST test vectors.

    This function tests classic modes of operation only.

    Args:
        encrypt: The function to test.
        mode: The mode of operation.
        key_length: The key length in bits. Used to only select test vectors that have
            keys with the given length.

    Returns:
        A dictionary of results. NIST vectors are separated in several files, each
        Results corresponds to a single file. The keys are the name of the files,
        prefixed by "NIST/encrypt/".
    """
    results_dict = ResultsDict()

    vectors = AesVectors.load(mode, key_length)

    for keylen in vectors.nist.keys():
        vectors_list = vectors.nist[keylen]
        for vector in track(
            vectors_list, f"[NIST] Encrypt AES-{keylen}-{str(mode)} vectors"
        ):
            results = Results(
                "AES",
                "test_encrypt (NIST)",
                "Tests an implementation of AES encryption with NIST vectors.",
                {
                    "mode": mode,
                    "key_length": key_length,
                    "test vectors file": vector.name,
                },
            )
            results_dict[f"NIST/encrypt/{vector.name}"] = results
            for tid, test in enumerate(vector.tests):
                test_type = TestType.VALID if test.is_valid else TestType.INVALID
                key = bytes.fromhex(test.key)
                pt = bytes.fromhex(test.plaintext)
                ct = bytes.fromhex(test.ciphertext)
                info = DebugInfo(tid, test_type, ["Compliance"])
                data = AesData(info, Operation.ENCRYPT, key, pt, ct, None)

                try:
                    match mode:
                        case Mode.ECB:
                            c = encrypt(key, pt)
                        case Mode.CBC | Mode.CTR | Mode.CFB | Mode.CFB8 | Mode.CFB128:
                            iv = bytes.fromhex(test.iv)
                            c = encrypt(key, pt, iv=iv)
                        case Mode.CBC_PKCS7:
                            iv = bytes.fromhex(test.iv)
                            c = encrypt(key, pt, iv=iv)
                            # TODO: improve this.
                            c = c[: len(ct)]
                    if c == ct:
                        info.result = True
                    else:
                        info.error_msg = "Wrong ciphertext"
                    data.result = c
                    results.add(data)
                except Exception as error:
                    info.error_msg = f"Encryption error: {str(error)}"
                    logger.debug("Encryption error", exc_info=True)
                    results.add(data)
                    continue

    return results_dict


def _test_nist_decrypt(
    decrypt: Decrypt, mode: Mode, key_length: KeyLength
) -> ResultsDict:
    """Tests the implementation using NIST test vectors.

    This function tests classic modes of operation only.

    Args:
        decrypt: The function to test.
        mode: The mode of operation.
        key_length: The key length in bits. Used to only select test vectors that have
            keys with the given length.

    Returns:
        A dictionary of results. NIST vectors are separated in several files, each
        Results corresponds to a single file. The keys are the name of the files,
        prefixed by "NIST/decrypt/".
    """
    results_dict = ResultsDict()

    vectors = AesVectors.load(mode, key_length)

    for keylen in vectors.nist.keys():
        vectors_list = vectors.nist[keylen]
        for vector in track(
            vectors_list, f"[NIST] Decrypt AES-{keylen}-{str(mode)} vectors"
        ):
            results = Results(
                "AES",
                "test_decrypt (NIST)",
                "Tests an implementation of AES decryption with NIST vectors.",
                {
                    "mode": mode,
                    "key_length": key_length,
                    "test vectors file": vector.name,
                },
            )
            results_dict[f"NIST/decrypt/{vector.name}"] = results
            for tid, test in enumerate(vector.tests):
                test_type = TestType.VALID if test.is_valid else TestType.INVALID
                key = bytes.fromhex(test.key)
                pt = bytes.fromhex(test.plaintext)
                ct = bytes.fromhex(test.ciphertext)
                iv = bytes.fromhex(test.iv) or None

                info = DebugInfo(tid, test_type, ["Compliance"])
                data = AesData(info, Operation.DECRYPT, key, ct, pt, iv=iv)

                try:
                    match mode:
                        case Mode.ECB:
                            p = decrypt(key, ct)
                        case Mode.CBC | Mode.CTR | Mode.CFB | Mode.CFB8 | Mode.CFB128:
                            p = decrypt(key, ct, iv=iv)
                        case Mode.CBC_PKCS7:
                            ct = _encrypt(mode, key, pt, iv=iv)
                            p = decrypt(key, ct, iv=iv)
                        case Mode.CFB | Mode.CFB8 | Mode.CFB128:
                            segment_size = 8 if mode == Mode.CFB8 else 128
                            p = decrypt(key, ct, iv=iv, segment_size=segment_size)
                except Exception as error:
                    info.error_msg = f"Decryption error: {str(error)}"
                    logger.debug("Decryption error", exc_info=True)
                    results.add(data)
                    continue
                if p == pt:
                    info.result = True
                else:
                    info.error_msg = "Wrong plaintext"
                data.result = p
                results.add(data)

    return results_dict


def _test_nist_aead_encrypt(
    encrypt: Encrypt, mode: Mode, key_length: KeyLength, iv_length: int = 0
) -> ResultsDict:
    """Tests the implementation with NIST test vectors.

    This function tests AEAD modes of operation only.

    Args:
        encrypt: The function to test.
        mode: The mode of operation.
        key_length: The key length in bits. Used to only select test vectors that have
            keys with the given length.
        iv_length: The length of the IV. Selects only the test vectors that have an IV
            of the given length. If 0, use any test vector available.

    Returns:
        A dictionary of results. NIST vectors are separated in several files, each
        Results corresponds to a single file. The keys are the name of the files,
        prefixed by "NIST/encrypt/".
    """
    results_dict = ResultsDict()

    vectors = AesVectors.load(mode, key_length)

    for keylen in vectors.nist.keys():
        vectors_list = vectors.nist.get(keylen, None)
        if vectors_list is None:
            continue
        for vector in track(
            vectors_list, f"[NIST] Encrypt AES-{keylen}-{str(mode)} vectors"
        ):
            if "dec" in vector.name:
                continue
            results = Results(
                "AES",
                "test_encrypt (NIST)",
                "Tests an implementation of AES encryption with NIST vectors.",
                {
                    "mode": mode,
                    "key_length": key_length,
                    "iv_length": iv_length,
                    "test vectors file": vector.name,
                },
            )
            results_dict[f"NIST/encrypt/{vector.name}"] = results
            for tid, test in enumerate(vector.tests):
                test_type = TestType.VALID if test.is_valid else TestType.INVALID
                key = bytes.fromhex(test.key)
                pt = bytes.fromhex(test.plaintext)
                ct = bytes.fromhex(test.ciphertext)
                iv = bytes.fromhex(test.iv)
                if iv_length > 0 and len(iv) * 8 != iv_length:
                    continue
                aad = bytes.fromhex(test.aad) if test.aad else None
                tag = bytes.fromhex(test.tag)
                mac_len = len(tag)
                flag = ["Compliance"] if pt else ["Compliance/EmptyPlaintext"]
                info = DebugInfo(tid, test_type, flag)
                data = AesData(
                    info,
                    Operation.ENCRYPT,
                    key,
                    pt,
                    ct,
                    iv=iv,
                    aad=aad,
                    expected_mac=tag,
                )

                try:
                    c, t = encrypt(key, pt, iv=iv, aad=aad, mac_len=mac_len)
                except Exception as error:
                    # Invalid tests are meant to fail so we count it as a pass.
                    if test_type == TestType.INVALID:
                        info.result = True
                    else:
                        info.error_msg = f"Encryption error: {str(error)}"
                        logger.debug("Encryption error", exc_info=True)
                    results.add(data)
                    continue

                data.result = c
                data.mac = t
                res = (c == ct) and (t == tag)
                match (test_type, res):
                    case (TestType.VALID, True) | (TestType.INVALID, False):
                        info.result = True
                    case (TestType.VALID, False) | (TestType.INVALID, True):
                        if test_type == TestType.INVALID:
                            info.error_msg = "Invalid ciphertext and MAC returned"
                        elif c != ct and t != tag:
                            info.error_msg = "Wrong ciphertext and MAC"
                        elif c != ct:
                            info.error_msg = "Wrong ciphertext"
                        else:
                            info.error_msg = "Wrong MAC"
                results.add(data)

    return results_dict


def _test_nist_aead_decrypt(
    decrypt: Decrypt, mode: Mode, key_length: KeyLength, iv_length: int = 0
) -> ResultsDict:
    """Tests the implementation with NIST test vectors.

    This function tests AEAD modes of operation only.

    Args:
        decrypt: The function to test.
        mode: The mode of operation.
        key_length: The key length in bits. Used to only select test vectors that have
            keys with the given length.
        iv_length: The length of the IV. Selects only the test vectors that have an IV
            of the given length. If 0, use any test vector available.

    Returns:
        A dictionary of results. NIST vectors are separated in several files, each
        Results corresponds to a single file. The keys are the name of the files,
        prefixed by "NIST/decrypt/".
    """
    results_dict = ResultsDict()

    vectors = AesVectors.load(mode, key_length)

    for keylen in vectors.nist.keys():
        vectors_list = vectors.nist.get(keylen, None)
        if vectors_list is None:
            continue
        for vector in track(
            vectors_list, f"[NIST] Decrypt AES-{keylen}-{str(mode)} vectors"
        ):
            if "enc" in vector.name:
                continue
            results = Results(
                "AES",
                "test_encrypt (NIST)",
                "Tests an implementation of AES decryption with NIST vectors.",
                {
                    "mode": mode,
                    "key_length": key_length,
                    "iv_length": iv_length,
                    "test vectors file": vector.name,
                },
            )
            results_dict[f"NIST/decrypt/{vector.name}"] = results
            for tid, test in enumerate(vector.tests):
                test_type = TestType.VALID if test.is_valid else TestType.INVALID
                key = bytes.fromhex(test.key)
                pt = bytes.fromhex(test.plaintext)
                ct = bytes.fromhex(test.ciphertext)
                iv = bytes.fromhex(test.iv)
                if iv_length > 0 and len(iv) * 8 != iv_length:
                    continue
                aad = bytes.fromhex(test.aad) if test.aad else None
                tag = bytes.fromhex(test.tag)
                mac_len = len(tag)
                flag = ["Compliance"] if ct else ["Compliance/EmptyCiphertext"]
                info = DebugInfo(tid, test_type, flag)
                data = AesData(
                    info,
                    Operation.DECRYPT,
                    key,
                    ct,
                    pt,
                    iv=iv,
                    aad=aad,
                    expected_mac=tag,
                )

                try:
                    p, status = decrypt(
                        key, ct, iv=iv, aad=aad, mac=tag, mac_len=mac_len
                    )
                except Exception as error:
                    # Invalid tests are meant to fail so we count it as a pass.
                    if test_type == TestType.INVALID:
                        info.result = True
                    else:
                        info.error_msg = f"Decryption error: {str(error)}"
                        logger.debug("Decryption error", exc_info=True)
                    results.add(data)
                    continue

                data.result = p
                data.valid_mac = status
                res = status and (p == pt)
                match (test_type, res):
                    case (TestType.VALID, True) | (TestType.INVALID, False):
                        info.result = True
                    case (TestType.VALID, False) | (TestType.INVALID, True):
                        if test_type == TestType.INVALID:
                            info.error_msg = "Invalid plaintext/MAC accepted"
                        elif not status:
                            info.error_msg = "MAC verification failed"
                        else:
                            info.error_msg = "Wrong plaintext"
                results.add(data)

    return results_dict


def _test_nist_vectors(
    encrypt: Encrypt | None,
    decrypt: Decrypt | None,
    mode: Mode,
    key_length: KeyLength,
    iv_length: int = 0,
) -> ResultsDict:
    """Tests using NIST test vectors.

    Args:
        encrypt: The encryption function to test. Use None to skip this test.
        decrypt: The decryption function to test. Use None to skip this test.
        mode: The mode of operation to test.
        key_length: The key length in bits. Used to only select test vectors that have
            keys with the given length.
        iv_length: The length of the IV to use. Some implementations only deal with IVs
            of specific sizes, so this option restricts the test vectors used to only
            those that have the correct IV length.

    Returns:
        A dictionary of results. NIST vectors are separated in several files, each
        Results corresponds to a single file. The keys are the name of the files,
        prefixed by "NIST/encrypt/" or "NIST/decrypt/".
    """
    results_dict = ResultsDict()

    if mode in Mode.classic_modes():
        if encrypt is not None:
            results_dict |= _test_nist_encrypt(encrypt, mode, key_length)
        if decrypt is not None:
            results_dict |= _test_nist_decrypt(decrypt, mode, key_length)
    else:
        if encrypt is not None:
            results_dict |= _test_nist_aead_encrypt(
                encrypt, mode, key_length, iv_length
            )
        if decrypt is not None:
            results_dict |= _test_nist_aead_decrypt(
                decrypt, mode, key_length, iv_length
            )

    return results_dict


def _test_wycheproof_encrypt(
    encrypt: Encrypt, mode: Mode, key_length: KeyLength, iv_length: int = 0
) -> Results | None:
    """Tests a mode of operation with Wycheproof test vectors.

    Args:
        encrypt: The function to test.
        mode: The mode of operation.
        key_length: The key length in bits. Used to only select test vectors that have
            keys with the given length.
        iv_length: The length of the IV to test. If 0, use any test vector available.

    Returns:
        The results of testing with Wycheproof vectors. Only one file is available per
        mode of operation. If there are no vectors for the given mode, returns None.
    """
    vectors = AesVectors.load(mode, key_length)
    if vectors.wycheproof is None:
        return None

    results = Results(
        "AES",
        "test_encryption (Wycheproof)",
        "Tests an implementation of AES encryption with Wycheproof vectors.",
        {"mode": mode, "key_length": key_length, "iv_length": iv_length},
    )

    for group in track(
        vectors.wycheproof["testGroups"],
        f"[Wycheproof] Encrypt AES-{key_length}-{str(mode)} vectors",
    ):
        for test in group["tests"]:
            key = bytes.fromhex(test["key"])
            # Skip tests that don't match key_length when used.
            if key_length > 0 and len(key) * 8 != key_length:
                continue
            iv = bytes.fromhex(test["iv"])
            # Skip tests that don't match iv_length when used.
            if iv_length > 0 and len(iv) * 8 != iv_length:
                continue
            plaintext = bytes.fromhex(test["msg"])
            ciphertext = bytes.fromhex(test["ct"])
            mac = bytes.fromhex(test.get("tag", ""))
            aad = bytes.fromhex(test.get("aad", ""))
            mac_len = len(mac)

            test_type = TestType(test["result"])
            if test["flags"]:
                flags = test["flags"]
            else:
                flags = ["Resilience"] if plaintext else ["Resilience/EmptyPlaintext"]
            info = DebugInfo(
                test["tcId"], test_type, flags, comment=test.get("comment", None)
            )
            data = AesData(
                info,
                Operation.ENCRYPT,
                key,
                plaintext,
                ciphertext,
                iv=iv,
                aad=aad,
                expected_mac=mac,
            )

            try:
                if mode == Mode.CBC_PKCS7:
                    ct, mt = encrypt(key, plaintext, iv=iv), None
                    res = ct[: len(ciphertext)] == ciphertext
                else:
                    ct, mt = encrypt(key, plaintext, iv=iv, aad=aad, mac_len=mac_len)
                    res = (ct == ciphertext) and (mt == mac)
            except Exception as error:
                # Invalid tests are meant to fail so we count it as a pass.
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
                    elif ct != ciphertext and mt != mac:
                        info.error_msg = "Wrong ciphertext and MAC"
                    elif ct != ciphertext:
                        info.error_msg = "Wrong ciphertext"
                    else:
                        info.error_msg = "Wrong MAC"
                case (TestType.ACCEPTABLE, (True | False)):
                    info.result = res
            results.add(data)

    return results


def _test_wycheproof_decrypt(
    decrypt: Decrypt, mode: Mode, key_length: KeyLength, iv_length: int = 0
) -> Results | None:
    """Tests a mode of operation with Wycheproof test vectors.

    Args:
        decrypt: The function to test.
        mode: The mode of operation.
        key_length: The key length in bits. Used to only select test vectors that have
            keys with the given length.
        iv_length: The length of the IV to test. If 0, use any test vector available.

    Returns:
        The results of testing with Wycheproof vectors. Only one file is available per
        mode of operation. If there are no vectors for the given mode, returns None.
    """
    vectors = AesVectors.load(mode, key_length)
    if vectors.wycheproof is None:
        return None

    results = Results(
        "AES",
        "test_decryption (Wycheproof)",
        "Tests an implementation of AES decryption with Wycheproof vectors.",
        {"mode": mode, "key_length": key_length, "iv_length": iv_length},
    )

    for group in track(
        vectors.wycheproof["testGroups"],
        f"[Wycheproof] Decrypt AES-{key_length}-{str(mode)} vectors",
    ):
        for test in group["tests"]:
            key = bytes.fromhex(test["key"])
            # Skip tests that don't match key_length when used.
            if key_length != 0 and len(key) * 8 != key_length:
                continue
            iv = bytes.fromhex(test["iv"])
            # Skip tests that don't match iv_length when used.
            if iv_length > 0 and len(iv) * 8 != iv_length:
                continue
            plaintext = bytes.fromhex(test["msg"])
            ciphertext = bytes.fromhex(test["ct"])
            mac = bytes.fromhex(test.get("tag", ""))
            aad = bytes.fromhex(test.get("aad", ""))

            test_type = TestType(test["result"])
            if test["flags"]:
                flags = test["flags"]
            else:
                flags = ["Resilience"] if plaintext else ["Resilience/EmptyCiphertext"]
            info = DebugInfo(
                test["tcId"], test_type, flags, comment=test.get("comment", None)
            )
            data = AesData(
                info,
                Operation.DECRYPT,
                key,
                ciphertext,
                plaintext,
                iv=iv,
                aad=aad,
                expected_mac=mac,
            )

            try:
                # CCM mode uses the mac_len parameter and omitting it makes some valid
                # tests fail.
                if mode == Mode.CCM:
                    mac_len = len(mac)
                    pt, status = decrypt(
                        key, ciphertext, iv=iv, aad=aad, mac=mac, mac_len=mac_len
                    )
                    res = status and (pt == plaintext)
                elif mode == Mode.GCM:
                    mac_len = len(mac)
                    pt, status = decrypt(
                        key, ciphertext, iv=iv, aad=aad, mac=mac, mac_len=mac_len
                    )
                    res = status and (pt == plaintext)
                else:
                    # Add a second argument to bound a value to status, which is
                    # used when adding the result.
                    pt, status = decrypt(key, ciphertext, iv=iv), True
                    res = pt[: len(plaintext)] == plaintext
            except Exception as error:
                # Invalid tests are meant to fail so we count it as a pass.
                if test_type == TestType.INVALID:
                    info.result = True
                else:
                    info.error_msg = f"Decryption error: {str(error)}"
                    logger.debug("Decryption error", exc_info=True)
                results.add(data)
                continue

            data.result = pt
            data.valid_mac = status
            match (test_type, res):
                case (TestType.VALID, True) | (TestType.INVALID, False):
                    info.result = True
                case (TestType.VALID, False) | (TestType.INVALID, True):
                    if test_type == TestType.INVALID:
                        info.error_msg = "Invalid input accepted"
                    elif not status:
                        info.error_msg = "MAC verification failed"
                    else:
                        info.error_msg = "Wrong plaintext"
                case (TestType.ACCEPTABLE, (True | False)):
                    info.result = res
            results.add(data)

    return results


def _test_wycheproof(
    encrypt: Encrypt | None,
    decrypt: Decrypt | None,
    mode: Mode,
    key_length: KeyLength,
    iv_length: int = 0,
) -> ResultsDict:
    """Tests an implementation using Wycheproof test vectors.

    Args:
        encrypt: The encryption function to test, use None to skip.
        decrypt: The decryption function to test, use None to skip.
        mode: The mode of operation to test.
        key_length: The key length in bits. Used to only select test vectors that have
            keys with the given length.
        iv_length: The length of the IV to test. If 0, use any test vector available.

    Returns:
        A dictionary of results. Since there is only one file of test vectors per mode
        of operation, results are simply indexed by "Wycheproof/encrypt" and
        "Wycheproof/decrypt". If there are no test vectors for the given mode, no
        results are included.
    """
    results_dict = ResultsDict()
    if encrypt is not None:
        encrypt_results = _test_wycheproof_encrypt(encrypt, mode, key_length, iv_length)
        if encrypt_results is not None:
            results_dict["Wycheproof encrypt"] = encrypt_results
    if decrypt is not None:
        decrypt_results = _test_wycheproof_decrypt(decrypt, mode, key_length, iv_length)
        if decrypt_results is not None:
            results_dict["Wycheproof decrypt"] = decrypt_results
    return results_dict


def test(
    encrypt: Encrypt | None,
    decrypt: Decrypt | None,
    mode: Mode,
    key_length: KeyLength,
    *,
    iv_length: int = 0,
    compliance: bool = True,
    resilience: bool = True,
) -> ResultsDict:
    """Tests implementations of AES encryption and decryption.

    It runs the given functions on a set of test vectors determined by the mode of
    operation, key length, selection of compliance or resilience test vectors, and the
    IV length.

    The functions to test must conform to the :protocol:`Encrypt` and
    :protocol:`Decrypt` protocols.

    Args:
        encrypt: The encryption function to test.
        decrypt: The decryption function to test.
        mode: The mode of operation to test.
        key_length: The size of the key in bits. Use 0 to test all three values.

    Keyword Args:
        iv_length: The length of the IV. This options restrict the test vectors to only
            those that use IVs of the given length. Set to 0 to use all test vectors.
        compliance: Whether to use compliance test vectors.
        resilience: Whether to use resilience test vectors.

    Returns:
        A dictionary of results.

        If the compliance option is True then NIST test vectors are used. They are
        separated in several files, each result corresponds to a single file and they
        are indexed by the file name, prefixed by ``NIST/encrypt/`` and
        ``NIST/decrypt/``.

        If the resilience option is True then Wycheproof test vectors are used, if
        Wycheproof supports the given mode of operation. The dictionary key for results
        of testing the encrypt function (resp. the decrypt function) is
        ``Wycheproof/encrypt/`` (resp. ``Wycheproof/decrypt/``).

    Example:
        Let's test PyCryptodome's implementation of AES-256-ECB.

        We start by importing the AES module.

        >>> from crypto_condor.primitives import AES

        We need to wrap the functions to match the signature defined by
        :protocol:`Encrypt` and :protocol:`Decrypt`. In this case, we want to match the
        first overload, as it is the one that corresponds to ECB.

        >>> from Crypto.Cipher import AES as pycAES

        >>> def my_enc(key: bytes, plaintext: bytes) -> bytes:
        ...     cipher = pycAES.new(key, pycAES.MODE_ECB)
        ...     return cipher.encrypt(plaintext)

        >>> def my_dec(key: bytes, ciphertext: bytes) -> bytes:
        ...     cipher = pycAES.new(key, pycAES.MODE_ECB)
        ...     return cipher.decrypt(ciphertext)

        We define the parameters to test using the corresponding enums.

        >>> mode = AES.Mode.ECB
        >>> keylen = AES.KeyLength.AES256

        And now we test the functions we defined.

        >>> results_dict = AES.test(my_enc, my_dec, mode, keylen)
        [NIST] ...
        >>> assert results_dict.check()

        Now let's try a more specific example: testing AES-256-GCM decryption with only
        IVs of size 96.

        >>> def my_gcm_dec(
        ...     key: bytes,
        ...     ciphertext: bytes,
        ...     *,
        ...     iv: bytes | None,
        ...     aad: bytes | None,
        ...     mac: bytes | None,
        ...     mac_len: int,
        ... ) -> tuple[bytes | None, bool]:
        ...     cipher = pycAES.new(key, pycAES.MODE_GCM, nonce=iv, mac_len=mac_len)
        ...     if aad is not None:
        ...         cipher.update(aad)
        ...     try:
        ...         plaintext = cipher.decrypt_and_verify(ciphertext, mac)
        ...         return (plaintext, True)
        ...     except ValueError:
        ...         return (None, False)

        >>> mode = AES.Mode.GCM
        >>> results_dict = AES.test(None, my_gcm_dec, mode, keylen, iv_length=96)
        [NIST] ...
        >>> assert results_dict.check()
    """
    results_dict = ResultsDict()
    if not compliance and not resilience:  # pragma: no cover (not interesting)
        return results_dict
    if compliance:
        results_dict |= _test_nist_vectors(
            encrypt, decrypt, mode, key_length, iv_length
        )
    if resilience:
        results_dict |= _test_wycheproof(encrypt, decrypt, mode, key_length, iv_length)
    return results_dict


def _verify_file_encrypt(filename: str, mode: Mode) -> Results:
    with open(filename, "r") as file:
        lines = file.readlines()
    logger.debug("Read %s lines from %s.", len(lines), filename)

    results = Results(
        "AES",
        "verify_file",
        "Checks the output of an implementation.",
        {"filename": filename, "mode": mode, "operation": Operation.ENCRYPT},
    )

    tid = 0
    for line_number, line in track(enumerate(lines, start=1), "Testing file"):
        if line.startswith("#"):
            continue
        tid += 1
        args = line.rstrip().split("/")
        info = DebugInfo(
            tid, TestType.VALID, ["UserInput"], comment=f"Line number {line_number}"
        )
        # Default values for non-AEAD modes.
        aad, mac, mt = None, None, None
        match mode:
            case Mode.ECB:
                key, plaintext, ciphertext = map(bytes.fromhex, args)
                iv = None
                ct = _encrypt(mode, key, plaintext)
            case (
                Mode.CBC
                | Mode.CTR
                | Mode.CBC_PKCS7
                | Mode.CFB
                | Mode.CFB8
                | Mode.CFB128
            ):
                key, plaintext, ciphertext, iv = map(bytes.fromhex, args)
                ct = _encrypt(mode, key, plaintext, iv=iv)
            case Mode.CCM | Mode.GCM:
                key, plaintext, ciphertext, iv, aad, mac = map(bytes.fromhex, args)
                ct, mt = _encrypt(
                    mode, key, plaintext, iv=iv, aad=aad, mac_len=len(mac)
                )
        # Works even for non-AEAD modes since mac and mt would be None.
        if ciphertext == ct and mac == mt:
            info.result = True
        elif ciphertext != ct and mac != mt:
            info.error_msg = "Wrong ciphertext and MAC"
        elif ciphertext != ct:
            info.error_msg = "Wrong ciphertext"
        else:
            info.error_msg = "Wrong MAC"
        data = AesData(
            info, Operation.ENCRYPT, key, plaintext, ct, ciphertext, iv, aad, mt, mac
        )
        results.add(data)

    return results


def _verify_file_decrypt(filename: str, mode: Mode) -> Results:
    with open(filename, "r") as file:
        lines = file.readlines()
    logger.debug("Read %s lines from %s.", len(lines), filename)

    results = Results(
        "AES",
        "verify_file",
        "Checks the output of an implementation.",
        {"filename": filename, "mode": mode, "operation": Operation.DECRYPT},
    )

    for tid, line in track(enumerate(lines, start=1), "Testing file"):
        if line.startswith("#"):
            continue
        args = line.rstrip().split("/")
        info = DebugInfo(
            tid, TestType.VALID, ["UserInput"], comment=f"Line number {tid}"
        )
        # Default values for non-AEAD modes.
        aad, mac, st = None, None, True
        pt: bytes | None
        match mode:
            case Mode.ECB:
                key, ciphertext, plaintext = map(bytes.fromhex, args)
                iv = None
                pt = _decrypt(mode, key, ciphertext)
            case (
                Mode.CBC
                | Mode.CTR
                | Mode.CBC_PKCS7
                | Mode.CFB
                | Mode.CFB8
                | Mode.CFB128
            ):
                key, ciphertext, plaintext, iv = map(bytes.fromhex, args)
                pt = _decrypt(mode, key, ciphertext, iv=iv)
            case Mode.CCM | Mode.GCM:
                key, ciphertext, plaintext, iv, aad, mac = map(bytes.fromhex, args)
                pt, st = _decrypt(
                    mode, key, ciphertext, iv=iv, aad=aad, mac=mac, mac_len=len(mac)
                )
        # Works even for non-AEAD modes since mac and mt would be None.
        if st and plaintext == pt:
            info.result = True
        elif not st:
            info.error_msg = "MAC verification failed"
        else:
            info.error_msg = "Wrong plaintext"
        data = AesData(
            info,
            Operation.DECRYPT,
            key,
            ciphertext,
            pt,
            plaintext,
            iv,
            aad,
            mac,
            valid_mac=st,
        )
        results.add(data)

    return results


def verify_file(filename: str, mode: Mode, operation: Operation) -> Results:
    r"""Tests the output of an implementation.

    Tests an implementation from a set of inputs passed to it and the outputs it
    returned. These inputs are passed to the internal implementation and the results
    are compared to the outputs given.

    .. attention::

        This function uses the internal implementation of AES, which must be compiled
        and installed locally. This is done automatically when the function is called
        for the first time. If the installation fails, this function will not work.

    Format:
        - One set of arguments per line.
        - Lines are separated by newlines (``\n``).
        - Lines that start with '#' are counted as comments and ignored.
        - Arguments are written in hexadecimal and separated by slashes.
        - For ECB the order is:

        .. code::

            key/input/output

        - For other classic modes of operation (CBC, CTR, CFB) the order is:

        .. code::

            key/input/output/iv

        - For AEAD modes (CCM, GCM) the order is:

        .. code::

            key/input/output/iv/[aad]/[mac]

        - Where:
            - ``key`` is the key used.
            - ``input`` is the plaintext when encrypting (resp. the ciphertext when
              decrypting).
            - ``output`` is the ciphertext when encrypting (resp. the plaintext when
              decrypting).
            - ``iv`` is the IV or nonce used for that operation.
            - ``aad`` is the associated data. It is optional and can be empty. Even if
              not used, the corresponding slashes must be present.
            - ``mac`` is the MAC tag generated when encrypting. When testing encryption,
              it is compared to the MAC generated internally. When decrypting, it is
              used for authenticating the ciphertext and associated data.

    Args:
        filename: The name of the file to test.
        mode: The mode of operation to use.
        operation: The operation being tested, 'encrypt' or 'decrypt'.

    Returns:
        The results of testing each line of the line.

    Raises:
        FileNotFoundError: If there is not file with that filename.

    Example:
        Let's generate 10 random tuples of (key, plaintext, IV), encrypt the plaintexts
        using PyCryptodome's AES-128-GCM, and write everything to a file. We won't use
        any associated data to illustrate how to skip it.

        >>> import random
        >>> from crypto_condor.primitives import AES
        >>> from Crypto.Cipher import AES as pyAES
        >>> filename = "/tmp/crypto-condor-test/aes-verify.txt"
        >>> with open(filename, "w") as file:
        ...     for _ in range(10):
        ...         # Pick random values.
        ...         key = random.randbytes(16)
        ...         plaintext = random.randbytes(16)
        ...         iv = random.randbytes(12)
        ...         # Encrypt.
        ...         cipher = pyAES.new(key, pyAES.MODE_GCM, nonce=iv)
        ...         ciphertext, mac = cipher.encrypt_and_digest(plaintext)
        ...         # Convert to hex.
        ...         kh = bytes.hex(key)
        ...         ph = bytes.hex(plaintext)
        ...         ih = bytes.hex(iv)
        ...         ch = bytes.hex(ciphertext)
        ...         mh = bytes.hex(mac)
        ...         # Create the line to write.
        ...         # key/input/output/iv/[aad]/[mac]
        ...         line = f"{kh}/{ph}/{ch}/{ih}//{mh}\n"
        ...         _ = file.write(line)

        Now we can test this file.

        >>> mode = AES.Mode.GCM
        >>> operation = AES.Operation.ENCRYPT
        >>> results = AES.verify_file(filename, mode, operation)
        Testing ...
        >>> assert results.check()
    """
    if not Path(filename).is_file():
        raise FileNotFoundError("Can't find file %s", filename)

    if operation == Operation.ENCRYPT:
        return _verify_file_encrypt(filename, mode)
    else:
        return _verify_file_decrypt(filename, mode)


if __name__ == "__main__":
    # Calling this module as a script installs the AES binary manually.
    _ = _get_aes_lib()
