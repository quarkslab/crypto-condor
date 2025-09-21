"""Tests for `crypto_condor.primitives.ed25519`."""

from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from crypto_condor.primitives import ed25519

from ..common import console


def test_sign():
    """Tests `ed25519.test_sign`."""

    def sign(sk: bytes, msg: bytes) -> bytes:
        key = Ed25519PrivateKey.from_private_bytes(sk)
        return key.sign(msg)

    rd = ed25519.test_sign(sign, True, True)
    console.print_results(rd)
    assert rd.check(fail_if_empty=True)


def test_verify():
    """Tests `ed25519.test_verify`."""

    def verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
        key = Ed25519PublicKey.from_public_bytes(pk)
        try:
            key.verify(sig, msg)
        except InvalidSignature:
            return False
        else:
            return True

    rd = ed25519.test_verify(verify, True, True)
    console.print_results(rd)
    assert rd.check(fail_if_empty=True)


def test_output_sign(tmp_path: Path):
    """Tests `ed25519.test_output_sign`."""
    variant = ed25519.Variant.ED25519
    vectype = ed25519.Vectype.SIGN
    test_vectors = ed25519._load_vectors(variant, vectype, True, True)

    output = tmp_path / "ed25519_test_output_sign.txt"
    with output.open("w") as fp:
        for vectors in test_vectors:
            fp.write(f"# Test vectors from {vectors.source}\n")
            for test in vectors.tests:
                line = f"{test.sk.hex()}/{test.msg.hex()}/{test.sig.hex()}\n"
                fp.write(line)

    rd = ed25519.test_output_sign(output)
    console.print_results(rd)
    assert rd.check(fail_if_empty=True)
