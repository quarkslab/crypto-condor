"""Enums for AES."""

import enum
from dataclasses import dataclass
from typing import Protocol

import strenum

# -------------------------------------------------------------------------------------
# Enums
# -------------------------------------------------------------------------------------


class KeyLength(enum.IntEnum):
    """Supported key lengths.

    AES has three different key lengths: 128, 192, and 256 bits. Since users may want to
    test a specific key length, this enum defines these three options alongside the
    :attr:`KeyLength.ALL` option to test all three.
    """

    ALL = 0
    AES128 = 128
    AES192 = 192
    AES256 = 256


class Mode(strenum.StrEnum):
    """Supported AES modes of operation."""

    ECB = "ECB"
    CBC = "CBC"
    CBC_PKCS7 = "CBC-PKCS7"
    CFB = "CFB"
    CFB8 = "CFB8"
    CFB128 = "CFB128"
    CTR = "CTR"
    GCM = "GCM"
    CCM = "CCM"

    @classmethod
    def classic_modes(cls):
        """Returns a list of all supported classic (non AEAD) modes.

        ``crypto-condor`` supports ECB, CBC, CBC with PKCS#7 padding, CFB8, CFB128, and
        CTR.
        """
        return [e for e in cls if str(e) not in {"GCM", "CCM"}]


# -------------------------------------------------------------------------------------
# Operations
# -------------------------------------------------------------------------------------


class Operation(enum.StrEnum):
    ENC = "encrypt"
    DEC = "decrypt"
    AEADENC = "aeadencrypt"
    AEADDEC = "aeaddecrypt"


class Encrypt(Protocol):
    def __call__(self, key: bytes, plaintext: bytes, iv: bytes) -> bytes: ...


class Decrypt(Protocol):
    def __call__(self, key: bytes, ciphertext: bytes, iv: bytes) -> bytes: ...


class AeadEncrypt(Protocol):
    def __call__(
        self, key: bytes, plaintext: bytes, nonce: bytes, aad: bytes, mac_len: int = 0
    ) -> tuple[bytes, bytes]: ...


class AeadDecrypt(Protocol):
    def __call__(
        self, key: bytes, ciphertext: bytes, nonce: bytes, aad: bytes, mac: bytes
    ) -> bytes: ...


# -------------------------------------------------------------------------------------
# Harness parser
# -------------------------------------------------------------------------------------


@dataclass
class AesOpts:
    op: Operation
    mode: Mode
    keylen: KeyLength
    aead: bool

    @classmethod
    def parse(cls, funcname: str):
        if not funcname.startswith("CC_AES_"):
            raise ValueError("FIXME")
        match funcname.split("_")[2:]:
            case _op, _mode:
                op = Operation(_op)
                mode = Mode(_mode)
            case _op, _mode, _keylen:
                op = Operation(_op)
                mode = Mode(_mode)
                keylen = KeyLength(int(_keylen))
            case _:
                # FIXME
                pass
        aead = mode not in Mode.classic_modes()
        return cls(op, mode, keylen, aead)
