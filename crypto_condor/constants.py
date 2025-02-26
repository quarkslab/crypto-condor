"""Global constants."""

from typing import TypedDict

import strenum


class Modes(TypedDict):
    """Modes that must be declared for each primitive."""

    audit: bool | None
    method: bool | None
    output: bool | None
    wrapper: bool | None
    harness: bool | None


class Primitive(strenum.StrEnum):
    """Supported primitives."""

    AES = "AES"
    CHACHA20 = "ChaCha20"
    ECDH = "ECDH"
    ECDSA = "ECDSA"
    FALCON = "Falcon"
    HMAC = "HMAC"
    MLDSA = "MLDSA"
    MLKEM = "MLKEM"
    RSASSA = "RSASSA"
    RSAES = "RSAES"
    SHA = "SHA"
    SHAKE = "SHAKE"
    SPHINCS = "SPHINCS+"

    def get_languages(self):
        """Returns the primitive's Wrapper enum.

        The Wrapper enum defines the wrapper languages supported by that primitive.
        """
        # Local import to avoid redefinition of the enum members.
        from crypto_condor.primitives import (
            AES,
            ECDH,
            ECDSA,
            HMAC,
            MLDSA,
            MLKEM,
            RSAES,
            RSASSA,
            SHA,
            SHAKE,
            ChaCha20,
        )

        match self:
            case Primitive.AES:
                return AES.Wrapper
            case Primitive.CHACHA20:
                return ChaCha20.Wrapper
            case Primitive.ECDH:
                return ECDH.Wrapper
            case Primitive.ECDSA:
                return ECDSA.Wrapper
            case Primitive.HMAC:
                return HMAC.Wrapper
            case Primitive.MLDSA:
                return MLDSA.Wrapper
            case Primitive.MLKEM:
                return MLKEM.Wrapper
            case Primitive.RSASSA:
                return RSASSA.Wrapper
            case Primitive.RSAES:
                return RSAES.Wrapper
            case Primitive.SHA:
                return SHA.Wrapper
            case Primitive.SHAKE:
                return SHAKE.Wrapper
            case _:
                return None


SUPPORTED_MODES: dict[Primitive, Modes] = {
    Primitive.AES: {
        "audit": False,
        "method": True,
        "output": True,
        "wrapper": True,
        "harness": True,
    },
    Primitive.ECDSA: {
        "audit": False,
        "method": True,
        "output": True,
        "wrapper": True,
        "harness": False,
    },
    Primitive.FALCON: {
        "audit": False,
        "method": True,
        "output": None,
        "wrapper": None,
        "harness": False,
    },
    Primitive.SPHINCS: {
        "audit": False,
        "method": True,
        "output": None,
        "wrapper": None,
        "harness": False,
    },
    Primitive.SHA: {
        "audit": False,
        "method": True,
        "output": True,
        "wrapper": True,
        "harness": True,
    },
    Primitive.SHAKE: {
        "audit": False,
        "method": True,
        "output": True,
        "wrapper": True,
        "harness": True,
    },
    Primitive.RSASSA: {
        "audit": False,
        "method": True,
        "output": False,
        "wrapper": True,
        "harness": False,
    },
    Primitive.RSAES: {
        "audit": False,
        "method": True,
        "output": False,
        "wrapper": True,
        "harness": False,
    },
    Primitive.CHACHA20: {
        "audit": False,
        "method": True,
        "output": True,
        "wrapper": True,
        "harness": False,
    },
    Primitive.HMAC: {
        "audit": False,
        "method": True,
        "output": False,
        "wrapper": True,
        "harness": False,
    },
    Primitive.ECDH: {
        "audit": False,
        "method": True,
        "output": False,
        "wrapper": True,
        "harness": True,
    },
    Primitive.MLDSA: {
        "audit": False,
        "method": True,
        "output": True,
        "wrapper": True,
        "harness": True,
    },
    Primitive.MLKEM: {
        "audit": False,
        "method": True,
        "output": True,
        "wrapper": True,
        "harness": True,
    },
}
"""Primitives and their supported CLI modes."""

SUPPORTED_PRIMITIVES = [str(p) for p in Primitive]
"""A list of all supported primitives."""

assert set([p for p in Primitive]) == set(SUPPORTED_MODES.keys())
