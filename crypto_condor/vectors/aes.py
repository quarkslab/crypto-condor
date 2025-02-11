"""Enums for AES."""

import enum

import strenum


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
