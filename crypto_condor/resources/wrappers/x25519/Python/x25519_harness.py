"""Harness template for X25519.

To test this harness, run:

    crypto-condor-cli test wrapper x25519 x25519_harness.py

For more options, run;

    crypto-condor-cli test wrapper x25519 --help

Alternatively, to use the Python API check out the
`crypto_condor.primitives.x25519.test_harness_python` function.
"""


def CC_x25519_exchange(secret_key: bytes, peer_key: bytes) -> bytes:
    """Performs an X25519 key exchange.

    Args:
        secret_key:
            "Our" secret key.
        peer_key:
            The "peer" public key.

    Returns:
        The resulting shared secret.
    """
    raise NotImplementedError()
