"""Wrapper example 2: PyCryptodome ECDH over P-192 using the public key.

Usage:
    This example implements the `exchange_nist` method using the provided public key
    instead of the coordinates. To run this wrapper, use:

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
        # We import the public key. This representation only contains the coordinates so
        # we have to specify the curve used manually.
        pub = ECC.import_key(pub_key, curve_name="P-192")
        priv = ECC.construct(curve="P-192", d=secret)
        # We run the key agreement with a KDF (key derivation function) that does
        # nothing, as crypto-condor expects the "raw" shared secret.
        shared = DH.key_agreement(static_priv=priv, static_pub=pub, kdf=lambda x: x)
        return shared

    def exchange_wycheproof(self, secret: int, pub_key: bytes) -> bytes:
        """ECDH exchange with Wycheproof vectors."""
        raise NotImplementedError
