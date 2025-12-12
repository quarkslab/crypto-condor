"""Python wrapper template for ECDSA.

To test this wrapper, run:

    crypto-condor-cli test wrapper ECDSA ecdsa_wrapper.py

For more options, run:

    crypto-condor-cli test wrapper ECDSA --help
"""


def CC_ECDSA_sign_p256_sha256_DER(sk: bytes, msg: bytes) -> bytes:
    """Signs a message with ECDSA.

    This example will use the P-256 curve, SHA-256 hash function, and DER-encoded keys.

    Args:
        sk:
            The private key in DER format.
        msg:
            The message to sign.

    Returns:
        The signature in DER format.
    """
    raise NotImplementedError


def CC_ECDSA_verify_p256_sha256_DER(pk: bytes, msg: bytes, sig: bytes) -> bool:
    """Verifies an ECDSA signature.

    This example will use the P-256 curve, SHA-256 hash function, and DER-encoded keys.

    Args:
        pk:
            The public key in DER format.
        msg:
            The message.
        sig:
            The signature to verify.

    Returns:
        True if the signature is valid, False otherwise.
    """
    raise NotImplementedError
