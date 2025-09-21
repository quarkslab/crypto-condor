"""Harness template for Ed25519.

To test this harness, run:

    crypto-condor-cli test wrapper ed25519 ed25519_harness.py

For more options, run;

    crypto-condor-cli test wrapper ed25519 --help

Alternatively, to use the Python API check out the
`crypto_condor.primitives.ed25519.test_harness_python` function.
"""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def CC_ed25519_sign(sk: bytes, msg: bytes) -> bytes:
    """Signs a message with Ed25519.

    Args:
        sk:
            The raw private key.
        msg:
            The message to sign.

    Returns:
        The signature.
    """
    key = Ed25519PrivateKey.from_private_bytes(sk)
    return key.sign(msg)


def CC_ed25519_verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
    """Verifies an Ed25519 signature.

    Args:
        pk:
            The raw public key.
        msg:
            The signed message.
        sig:
            The signature to verify.

    Returns:
        True if the signature is valid, False otherwise.
    """
    key = Ed25519PublicKey.from_public_bytes(pk)
    try:
        key.verify(sig, msg)
    except InvalidSignature:
        return False
    except Exception:
        raise
    else:
        return True
