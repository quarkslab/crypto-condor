"""Wrapper example 1: PyCryptodome ECDH over P-192.

Usage:
    This example implements both methods of the CC_ECDH class to test the PyCryptodome
    with both NIST and Wycheproof vectors. To run this wrapper, use:

    crypto-condor-cli test wrapper ECDH P-129
"""

from Crypto.Protocol import DH
from Crypto.PublicKey import ECC


class CC_ECDH:
    """Implements the crypto_condor.primitives.ECDH.ECDH protocol."""

    def exchange_nist(
        self, secret: int, pub_x: int, pub_y: int, pub_key: bytes
    ) -> bytes:
        """ECDH exchange with NIST vectors."""
        # We can directly create the public key from the coordinates.
        pub = ECC.construct(curve="P-192", point_x=pub_x, point_y=pub_y)
        # Same goes for the private key and the private value.
        priv = ECC.construct(curve="P-192", d=secret)
        # We run the key agreement with a KDF (key derivation function) that does
        # nothing, as crypto-condor expects the "raw" shared secret.
        shared = DH.key_agreement(static_priv=priv, static_pub=pub, kdf=lambda x: x)
        return shared

    def exchange_wycheproof(self, secret: int, pub_key: bytes) -> bytes:
        """ECDH exchange with Wycheproof vectors."""
        # For Wycheproof, the public key can be directly imported. The curve used is
        # included in the key itself.
        pub = ECC.import_key(pub_key)
        # No difference for the private key.
        priv = ECC.construct(curve="P-192", d=secret)
        # Also no change for the exchange.
        shared = DH.key_agreement(static_priv=priv, static_pub=pub, kdf=lambda x: x)
        return shared
