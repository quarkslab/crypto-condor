"""Wrapper for ML-KEM implementations."""


def CC_MLKEM_512_encaps(pk: bytes) -> tuple[bytes, bytes]:
    """Generates and encapsulates a shared secret.

    Args:
        pk: The public key to encapsulate the secret with.

    Returns:
        A tuple (ct, ss) containing the shared secret (ss) and ciphertext (ct).
    """
    raise NotImplementedError


def CC_MLKEM_512_decaps(sk: bytes, ct: bytes) -> bytes:
    """Decapsulates a shared secret.

    Args:
        sk: The secret key to use.
        ct: The ciphertext to decapsulate.

    Returns:
        The decapsulated shared secret.
    """
    raise NotImplementedError


def CC_MLKEM_768_encaps(pk: bytes) -> tuple[bytes, bytes]:
    """Generates and encapsulates a shared secret.

    Args:
        pk: The public key to encapsulate the secret with.

    Returns:
        A tuple (ct, ss) containing the shared secret (ss) and ciphertext (ct).
    """
    raise NotImplementedError


def CC_MLKEM_768_decaps(sk: bytes, ct: bytes) -> bytes:
    """Decapsulates a shared secret.

    Args:
        sk: The secret key to use.
        ct: The ciphertext to decapsulate.

    Returns:
        The decapsulated shared secret.
    """
    raise NotImplementedError


def CC_MLKEM_1024_encaps(pk: bytes) -> tuple[bytes, bytes]:
    """Generates and encapsulates a shared secret.

    Args:
        pk: The public key to encapsulate the secret with.

    Returns:
        A tuple (ct, ss) containing the shared secret (ss) and ciphertext (ct).
    """
    raise NotImplementedError


def CC_MLKEM_1024_decaps(sk: bytes, ct: bytes) -> bytes:
    """Decapsulates a shared secret.

    Args:
        sk: The secret key to use.
        ct: The ciphertext to decapsulate.

    Returns:
        The decapsulated shared secret.
    """
    raise NotImplementedError
