"""Tests for :mod:`crypto_condor.primitives.x25519`."""

from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from crypto_condor.primitives import x25519

from ..common import console


def test_exchange():
    """Tests `x25519.test_exchange`."""

    def exchange(sk: bytes, pk: bytes) -> bytes:
        own_key = X25519PrivateKey.from_private_bytes(sk)
        peer_key = X25519PublicKey.from_public_bytes(pk)
        return own_key.exchange(peer_key)

    rd = x25519.test_exchange(exchange, True, True)
    console.print_results(rd)
    assert rd.check(fail_if_empty=True)


def test_output_exchange(tmp_path: Path):
    """Tests `x25519.test_output_exchange`."""
    # TODO: also use resilience test vectors? In that case, we have to only pick valid
    # ones.
    test_vectors = x25519._load_vectors(True, False)

    output = tmp_path / "x25519_test_output_exchange.txt"
    with output.open("w") as fp:
        for vectors in test_vectors:
            fp.write(f"# Test vectors from {vectors.source}\n")
            for test in vectors.tests:
                line = f"{test.sk.hex()}/{test.pk.hex()}/{test.shared.hex()}\n"
                fp.write(line)

    rd = x25519.test_output_exchange(output)
    console.print_results(rd)
    assert rd.check(fail_if_empty=True)
