"""Wrapper example for ML-DSA.

Uses the internal implementation, which calls the reference implementation from the
Dilithium submission.
"""

from crypto_condor.primitives import MLDSA


def CC_MLDSA_44_sign(sk: bytes, msg: bytes, ctx: bytes) -> bytes:
    """Signs a message.

    Args:
        sk: The secret key to use.
        msg: The message to sign.
        ctx: The context string. Can be an empty bytestring.

    Returns:
        The signed message, i.e. the concatenation of the signature and the message.
    """
    return MLDSA._sign(MLDSA.Paramset.ML_DSA_44, sk, msg, ctx)


def CC_MLDSA_44_verify(pk: bytes, sig: bytes, msg: bytes | None, ctx: bytes) -> bool:
    """Verifies an ML-DSA signature.

    Args:
        pk: The public key to use.
        sig: The signature to verify. If msg is None, it is the signed message
            (signature and message concatenated), else it is just the signature.
        msg: The message that was signed.
        ctx: The context string. Can be an empty bytestring.

    Returns:
        True if the signature is valid, False otherwise.
    """
    return MLDSA._verify(MLDSA.Paramset.ML_DSA_44, pk, sig, msg, ctx)


def CC_MLDSA_65_sign(sk: bytes, msg: bytes, ctx: bytes) -> bytes:
    """Signs a message.

    Args:
        sk: The secret key to use.
        msg: The message to sign.
        ctx: The context string. Can be an empty bytestring.

    Returns:
        The signed message, i.e. the concatenation of the signature and the message.
    """
    return MLDSA._sign(MLDSA.Paramset.ML_DSA_65, sk, msg, ctx)


def CC_MLDSA_65_verify(pk: bytes, sig: bytes, msg: bytes | None, ctx: bytes) -> bool:
    """Verifies an ML-DSA signature.

    Args:
        pk: The public key to use.
        sig: The signature to verify. If msg is None, it is the signed message
            (signature and message concatenated), else it is just the signature.
        msg: The message that was signed.
        ctx: The context string. Can be an empty bytestring.

    Returns:
        True if the signature is valid, False otherwise.
    """
    return MLDSA._verify(MLDSA.Paramset.ML_DSA_65, pk, sig, msg, ctx)


def CC_MLDSA_87_sign(sk: bytes, msg: bytes, ctx: bytes) -> bytes:
    """Signs a message.

    Args:
        sk: The secret key to use.
        msg: The message to sign.
        ctx: The context string. Can be an empty bytestring.

    Returns:
        The signed message, i.e. the concatenation of the signature and the message.
    """
    return MLDSA._sign(MLDSA.Paramset.ML_DSA_87, sk, msg, ctx)


def CC_MLDSA_87_verify(pk: bytes, sig: bytes, msg: bytes | None, ctx: bytes) -> bool:
    """Verifies an ML-DSA signature.

    Args:
        pk: The public key to use.
        sig: The signature to verify. If msg is None, it is the signed message
            (signature and message concatenated), else it is just the signature.
        msg: The message that was signed.
        ctx: The context string. Can be an empty bytestring.

    Returns:
        True if the signature is valid, False otherwise.
    """
    return MLDSA._verify(MLDSA.Paramset.ML_DSA_87, pk, sig, msg, ctx)
