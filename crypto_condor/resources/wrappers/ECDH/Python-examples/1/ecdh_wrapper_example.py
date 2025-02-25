"""ECDH Wrapper example using PyCryptodome.

Usage:

    crypto-condor-cli test wrapper ECDH ecdh_wrapper_example.py
"""

from Crypto.Protocol import DH
from Crypto.PublicKey import ECC


def CC_ECDH_exchange_point_P256(secret: bytes, pub_point: bytes) -> bytes:
    """Test ECDH exchange over P-256 using public coordinates."""
    # We can create the public key from the encoded point.
    pk = ECC.import_key(pub_point, curve_name="P-256")
    # Then derive the secret key from the secret value. ``construct`` expects an
    # integer, so first we convert.
    d = int.from_bytes(secret)
    sk = ECC.construct(curve="P-256", d=d)
    # We run the key agreement with a KDF (key derivation function) that does
    # nothing, as crypto-condor expects the "raw" shared secret.
    shared = DH.key_agreement(static_priv=sk, static_pub=pk, kdf=lambda x: x)
    return shared


def CC_ECDH_exchange_x509_P256(secret: bytes, pub_key: bytes) -> bytes:
    """Test ECDH exchange over P-256 using public X509 key."""
    # We can directly import the key, as it includes the curve information.
    pk = ECC.import_key(pub_key)
    # No difference for the private key.
    d = int.from_bytes(secret)
    sk = ECC.construct(curve="P-256", d=d)
    # Also no change for the exchange.
    shared = DH.key_agreement(static_priv=sk, static_pub=pk, kdf=lambda x: x)
    return shared
