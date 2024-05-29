"""Example 1: Internal implementation.

This example uses our internal implementation, which is a wrapper around the
reference implementation from the NIST submission package for Round 3.
"""

from crypto_condor.primitives import Kyber


def encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
    """Generates a random secret and encapsulates it.

    Args:
        public_key:
            The public key to use for encapsulating the generated secret.

    Returns:
        A tuple (ct, ss) containing the generated secret ss and the resulting
        ciphertext ct.
    """
    return Kyber._encapsulate(Kyber.Paramset.KYBER512, public_key)


def decapsulate(secret_key: bytes, ciphertext: bytes) -> bytes:
    """Decapsulates a ciphertext containing a generated secret.

    Args:
        secret_key:
            The secret key to use for decapsulating the ciphertext.
        ciphertext:
            A ciphertext of the shared secret.

    Returns:
        The generated shared secret.
    """
    return Kyber._decapsulate(Kyber.Paramset.KYBER512, secret_key, ciphertext)
