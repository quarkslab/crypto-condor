"""Tests for :mod:`crypto_condor.primitives.lib_hook`."""

import subprocess
import sys
from pathlib import Path

import pytest

from crypto_condor import harness
from crypto_condor.primitives.common import Console

console = Console()
# We assume that tests are run from the root of the repository.
ROOT_DIR = Path("tests/harness")


@pytest.mark.skipif(sys.platform != "linux", reason="dlopen's library in .local/share")
@pytest.mark.parametrize(
    "primitive",
    [
        "AES_openssl_encrypt",
        "AES_openssl_decrypt",
        pytest.param(
            "AES_openssl_encrypt_aead",
            marks=pytest.mark.xfail(
                reason="OpenSSL limits the size of GCM nonce to 128 bytes"
            ),
        ),
        pytest.param(
            "AES_openssl_decrypt_aead",
            marks=pytest.mark.xfail(
                reason="OpenSSL limits the size of GCM nonce to 128 bytes"
            ),
        ),
        "chacha20_openssl_encrypt",
        "chacha20_openssl_decrypt",
        "chacha20_poly1305_openssl_encrypt",
        "chacha20_poly1305_openssl_decrypt",
        "ECDH_point",
        "ECDH_x509",
        "HMAC_digest",
        "HMAC_verify",
        "MLDSA",
        "MLKEM",
        "SHA",
        "SHAKE",
    ],
)
def test_harness(primitive: str):
    """Tests harnesses with :func:`crypto_condor.harness.test_harness`."""
    # Compile the hook
    subprocess.run(["make", "-C", ROOT_DIR, f"{primitive}.harness.so"], check=True)

    file = ROOT_DIR / f"{primitive}.harness.so"
    rd = harness.test_harness(file, resilience=True)

    # Clean up
    file.unlink()

    console.print_results(rd)
    assert rd.check(fail_if_empty=True)
