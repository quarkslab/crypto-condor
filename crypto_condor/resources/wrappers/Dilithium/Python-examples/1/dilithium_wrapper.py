"""Example 1: Internal implementation.

This example uses our internal implementation, which is a wrapper around the
reference implementation from the NIST submission package for Round 3.
"""

from crypto_condor.primitives import Dilithium


def sign(secret_key: bytes, message: bytes) -> bytes:
    """Signs a message.

    Args:
        secret_key:
            The secret key.
        message:
            The message to sign.

    Returns:
        The computed signature.
    """
    return Dilithium._sign(Dilithium.Paramset.DILITHIUM2, secret_key, message)


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verifies a signed message.

    Args:
        public_key:
            The public key.
        message:
            The signed message.
        signature:
            The signature to verify.

    Returns:
        True if the signature is valid, False otherwise.
    """
    return Dilithium._verify(
        Dilithium.Paramset.DILITHIUM2, public_key, message, signature
    )
