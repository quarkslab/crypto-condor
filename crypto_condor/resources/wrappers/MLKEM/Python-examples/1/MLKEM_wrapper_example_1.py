"""Wrapper example for ML-KEM.

Uses the internal implementation, which calls the reference implementation from the
Kyber submission.
"""

from crypto_condor.primitives import MLKEM


def CC_MLKEM_512_encaps(pk: bytes) -> tuple[bytes, bytes]:
    """Generates and encapsulates a shared secret.

    Args:
        pk: The public key to encapsulate the secret with.

    Returns:
        A tuple (ct, ss) containing the shared secret (ss) and ciphertext (ct).
    """
    return MLKEM._encaps(MLKEM.Paramset.MLKEM512, pk)


def CC_MLKEM_512_decaps(sk: bytes, ct: bytes) -> bytes:
    """Decapsulates a shared secret.

    Args:
        sk: The secret key to use.
        ct: The ciphertext to decapsulate.

    Returns:
        The decapsulated shared secret.
    """
    return MLKEM._decaps(MLKEM.Paramset.MLKEM512, sk, ct)


def CC_MLKEM_768_encaps(pk: bytes) -> tuple[bytes, bytes]:
    """Generates and encapsulates a shared secret.

    Args:
        pk: The public key to encapsulate the secret with.

    Returns:
        A tuple (ct, ss) containing the shared secret (ss) and ciphertext (ct).
    """
    return MLKEM._encaps(MLKEM.Paramset.MLKEM768, pk)


def CC_MLKEM_768_decaps(sk: bytes, ct: bytes) -> bytes:
    """Decapsulates a shared secret.

    Args:
        sk: The secret key to use.
        ct: The ciphertext to decapsulate.

    Returns:
        The decapsulated shared secret.
    """
    return MLKEM._decaps(MLKEM.Paramset.MLKEM768, sk, ct)


def CC_MLKEM_1024_encaps(pk: bytes) -> tuple[bytes, bytes]:
    """Generates and encapsulates a shared secret.

    Args:
        pk: The public key to encapsulate the secret with.

    Returns:
        A tuple (ct, ss) containing the shared secret (ss) and ciphertext (ct).
    """
    return MLKEM._encaps(MLKEM.Paramset.MLKEM1024, pk)


def CC_MLKEM_1024_decaps(sk: bytes, ct: bytes) -> bytes:
    """Decapsulates a shared secret.

    Args:
        sk: The secret key to use.
        ct: The ciphertext to decapsulate.

    Returns:
        The decapsulated shared secret.
    """
    return MLKEM._decaps(MLKEM.Paramset.MLKEM1024, sk, ct)
