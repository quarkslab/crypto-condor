"""Wrapper template for RSA signature implementations."""


def sign(secret_key: bytes, message: bytes) -> bytes:
    """Wrapper function for signature generation.

    For RSASSA-PKCS1-v1_5 and RSASSA-PSS.

    Args:
        secret_key: The key to sign with, in PEM format.
        message: The message to sign.

    Returns:
        The signature.
    """
    raise NotImplementedError


def pkcs_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Wrapper function for RSASSA-PKCS1-v1_5 signature verification.

    Args:
        public_key: The public key to use, in PEM format.
        message: The message that was signed.
        signature: The resulting signature.

    Returns:
        True if the signature is valid, False otherwise.
    """
    raise NotImplementedError


def pss_verify(
    public_key: bytes, message: bytes, signature: bytes, salt_length: int = -1
) -> bool:
    """Wrapper function for RSASSA-PSS signature verification.

    Args:
        public_key: The public key to use, in PEM format.
        message: The message that was signed.
        signature: The resulting signature.
        salt_length: The length of the salt in bytes.

    Returns:
        True if the signature is valid, False otherwise.

    Notes:
        salt_length should always be greater or equal to 0. If for some reason
        the implementation receives -1, please create an issue.
    """
    raise NotImplementedError
