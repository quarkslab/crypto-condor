"""Wrapper template for HQC implementations."""


def CC_HQC_128_encaps(pk: bytes) -> tuple[bytes, bytes]:
    """Wrapper function for encapsulation with HQC-128.

    Args:
        pk:
            The public key.

    Returns:
        A tuple ``(ct, ss)`` containing the ciphertext ``ct`` and shared secret ``ss``.
    """
    raise NotImplementedError()


def CC_HQC_128_decaps(sk: bytes, ct: bytes) -> bytes:
    """Wrapper function for decapsulation with HQC-128.

    Args:
        sk:
            The secret key.
        ct:
            The ciphertext.

    Returns:
        The decapsulated shared secret.
    """
    raise NotImplementedError()


def CC_HQC_128_invariant() -> None:
    """Wrapper stub function for testing encapsulation-decapsulation with HQC-128."""
    pass
