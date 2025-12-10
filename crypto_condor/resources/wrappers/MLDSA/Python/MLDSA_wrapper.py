"""Wrapper template for ML-DSA implementations."""


def CC_MLDSA_sign_mldsa44(sk: bytes, msg: bytes, ctx: bytes) -> bytes:
    """Signs a message.

    Args:
        sk:
            The secret key to use.
        msg:
            The message to sign.
        ctx:
            The context string. Can be an empty bytestring.

    Returns:
        The signed message, i.e. the concatenation of the signature and the message.
    """
    raise NotImplementedError


def CC_MLDSA_verify_mldsa44(pk: bytes, sig: bytes, msg: bytes, ctx: bytes) -> bool:
    """Verifies an ML-DSA signature.

    Args:
        pk:
            The public key to use.
        sig:
            The signature to verify.
        msg:
            The message that was signed.
        ctx:
            The context string. Can be an empty bytestring.

    Returns:
        True if the signature is valid, False otherwise.
    """
    raise NotImplementedError
