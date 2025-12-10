"""Wrapper example for ML-DSA.

Uses the internal implementation, which calls the reference implementation from the
Dilithium submission.
"""

from crypto_condor.primitives import MLDSA


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
    return MLDSA._sign(MLDSA.Paramset.ML_DSA_44, sk, msg, ctx)


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
    return MLDSA._verify(MLDSA.Paramset.ML_DSA_44, pk, sig, msg, ctx)


def CC_MLDSA_sign_mldsa65(sk: bytes, msg: bytes, ctx: bytes) -> bytes:
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
    return MLDSA._sign(MLDSA.Paramset.ML_DSA_65, sk, msg, ctx)


def CC_MLDSA_verify_mldsa65(pk: bytes, sig: bytes, msg: bytes, ctx: bytes) -> bool:
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
    return MLDSA._verify(MLDSA.Paramset.ML_DSA_65, pk, sig, msg, ctx)


def CC_MLDSA_sign_mldsa87(sk: bytes, msg: bytes, ctx: bytes) -> bytes:
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
    return MLDSA._sign(MLDSA.Paramset.ML_DSA_87, sk, msg, ctx)


def CC_MLDSA_verify_mldsa87(pk: bytes, sig: bytes, msg: bytes, ctx: bytes) -> bool:
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
    return MLDSA._verify(MLDSA.Paramset.ML_DSA_87, pk, sig, msg, ctx)
