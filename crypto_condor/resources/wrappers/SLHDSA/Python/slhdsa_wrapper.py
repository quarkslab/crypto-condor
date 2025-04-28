"""Wrapper example for SLH-DSA."""


def CC_SLHDSA_sha2_128s_sign_pure(sk: bytes, msg: bytes, ctx: bytes, ph: str) -> bytes:
    """Signs with SLH-DSA.

    Args:
        sk:
            The secret key.
        msg:
            The message to sign.
        ctx:
            The context string. It can be empty.
        ph:
            For the pre-hash variant only, the name of the pre-hash function. For
            the pure variant, it is an empty string and should be ignored.

    Returns:
        The signature.
    """
    raise NotImplementedError()


def CC_SLHDSA_sha2_128s_verify_pure(
    pk: bytes, msg: bytes, sig: bytes, ctx: bytes, ph: str
) -> bool:
    """Verifies SLH-DSA signatures.

    Args:
        pk:
            The public key.
        msg:
            The message.
        sig:
            The signature.
        ctx:
            The context string. It can be empty.
        ph:
            For the pre-hash variant only, the name of the pre-hash function. For
            the pure variant, it is an empty string and should be ignored.

    Returns:
        True if the signature is valid, False otherwise.
    """
    raise NotImplementedError()


def CC_SLHDSA_sha2_128s_invariant_pure():
    """Stub to test the sign-verify invariant."""
    return
