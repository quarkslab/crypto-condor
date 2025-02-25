"""Tests for :mod:`crypto_condor.primitives.ECDH`."""

import pytest
from Crypto.Protocol import DH
from Crypto.PublicKey import ECC

from crypto_condor.primitives import ECDH

Curve = ECDH.Curve


@pytest.mark.parametrize(
    ("name", "ref_curve"),
    [
        ("P-256", Curve.P256),
        ("P256", Curve.P256),
        ("p256", Curve.P256),
        ("B-571", Curve.B571),
        ("b571", Curve.B571),
        ("brainpoolp256r1", Curve.BRAINPOOLP256R1),
        ("secp256k1", Curve.SECP256K1),
    ],
)
def test_from_name(name: str, ref_curve: Curve):
    """Tests :meth:`crypto_condor.primitives.ECDH.Curve.from_name`."""
    curve = Curve.from_name(name)
    assert curve == ref_curve


class EcdhInstance:
    """Instance of ``ECDH`` protocol."""

    def __init__(self, curve: str):
        self.curve = curve

    def exchange_nist(
        self, secret: int, pub_x: int, pub_y: int, pub_key: bytes
    ) -> bytes:
        """Tests key exchange with NIST vectors."""
        pk = ECC.construct(curve=self.curve, point_x=pub_x, point_y=pub_y)
        sk = ECC.construct(curve=self.curve, d=secret)
        ss = DH.key_agreement(static_priv=sk, static_pub=pk, kdf=lambda x: x)
        return ss

    def exchange_wycheproof(self, secret: int, public_key: bytes) -> bytes:
        """Tests key exchange with Wycheproof vectors."""
        pk = ECC.import_key(public_key)
        sk = ECC.construct(curve=self.curve, d=secret)
        ss = DH.key_agreement(static_priv=sk, static_pub=pk, kdf=lambda x: x)
        return ss

@pytest.mark.parametrize("curve", [Curve.P256, Curve.P521])
def test_exchange(curve: Curve):
    """Tests :func:`crypto_condor.primitives.ECDH.test_exchange`."""
    ecdh = EcdhInstance(str(curve))
    rd = ECDH.test_exchange_wycheproof(ecdh, curve)
    print(rd)
    assert rd.check()
