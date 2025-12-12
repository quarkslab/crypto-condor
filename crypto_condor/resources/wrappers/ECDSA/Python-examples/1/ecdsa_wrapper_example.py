"""ECDSA wrapper example with `cryptography`.

To run this example:

    crypto-condor-cli test wrapper ECDSA ECDSA_wrapper_example.py
"""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


def CC_ECDSA_sign_p256_sha256_DER(sk: bytes, msg: bytes) -> bytes:
    """Signature example.

    Signing over P-256, using SHA-256, and DER-encoded keys.
    """
    key = serialization.load_der_private_key(sk, None)
    return key.sign(msg, ec.ECDSA(hashes.SHA256()))  # type: ignore


def CC_ECDSA_sign_p521_sha256_DER(sk: bytes, msg: bytes) -> bytes:
    """Signature example.

    Same as above, using P-521. Note that DER-encoded keys contain information on the
    curve used, so the code to load them is the same.
    """
    key = serialization.load_der_private_key(sk, None)
    return key.sign(msg, ec.ECDSA(hashes.SHA256()))  # type: ignore


def CC_ECDSA_sign_p521_sha512256_DER(sk: bytes, msg: bytes) -> bytes:
    """Signature example.

    This also works for truncated hashes like SHA-512/256. Since slashes aren't accepted
    in function names, we simply remove them, the runner will parse it as SHA-512/256.
    """
    key = serialization.load_der_private_key(sk, None)
    return key.sign(msg, ec.ECDSA(hashes.SHA512_256()))  # type: ignore


def CC_ECDSA_sign_p521_sha512256_INT(sk: bytes, msg: bytes) -> bytes:
    """Signature example.

    We can also use other private key encodings. In this case INT corresponds to the
    private value, passed in bytes. `cryptography` can construct the private key from
    this value but it needs to know which curve we want to use.
    """
    key = ec.derive_private_key(int.from_bytes(sk, "big"), ec.SECP521R1())
    return key.sign(msg, ec.ECDSA(hashes.SHA512_256()))  # type: ignore


def CC_ECDSA_sign_p521_sha512256_PEM(sk: bytes, msg: bytes) -> bytes:
    """Signature example.

    Finally, we can use PEM keys too.
    """
    key = serialization.load_pem_private_key(sk, None)
    return key.sign(msg, ec.ECDSA(hashes.SHA512_256()))  # type: ignore


def CC_ECDSA_verify_p256_sha256_DER(pk: bytes, msg: bytes, sig: bytes) -> bool:
    """Verification example.

    The same naming principle applies to signature verification.
    """
    # Keys given by test vectors are supposed to be valid so key loading shouldn't raise
    # exceptions. In case it _does_ raise one, crypto-condor will catch it and count the
    # test as failed.
    # Alternatively, we could catch and re-raise, so that we have more details on why
    # the loading failed and still pass the exception to crypto-condor.
    key = serialization.load_der_public_key(pk)

    # To conform to the Verify protocol, we return False if the signature is invalid.
    # Since verify() throws InvalidSignature in that case, we catch it and return False
    # instead. We _only_ catch InvalidSignature, as other exceptions indicate a real
    # error; we let crypto-condor catch it and mark the test as failed.
    try:
        key.verify(sig, msg, ec.ECDSA(hashes.SHA256()))  # type: ignore
        return True
    except InvalidSignature:
        return False


def CC_ECDSA_signthenver_p256_sha256_DER() -> bool:
    """Signing then verifying example.

    This is a simple function to tell crypto-condor to test signing and verifying
    consecutively with a given set of parameters. For this test to work, the
    corresponding CC_ECDSA_sign and CC_ECDSA_verify functions must be implemented.
    """
    return True
