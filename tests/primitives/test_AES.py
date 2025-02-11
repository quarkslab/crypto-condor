"""Module to test the AES primitive."""

import pytest

from crypto_condor.primitives import AES
from crypto_condor.primitives.common import Console

console = Console()


@pytest.mark.parametrize("mode", AES.Mode)
def test_encrypt(mode: AES.Mode):
    """Tests internal encryption."""

    def _encrypt(key, pt, *, iv=None, aad=None, mac_len=0):
        return AES._encrypt(mode, key, pt, iv=iv, aad=aad, mac_len=mac_len)

    rd = AES.test_encrypt(_encrypt, mode, AES.KeyLength.ALL, resilience=True)
    console.print_results(rd)
    assert rd.check()


@pytest.mark.parametrize("mode", AES.Mode)
def test_decrypt(mode: AES.Mode):
    """Tests internal decryption."""

    def _decrypt(
        key, ct, *, iv=None, segment_size=0, aad=None, mac=None, mac_len=0, tag=None
    ):
        return AES._decrypt(mode, key, ct, iv=iv, aad=aad, mac=mac, mac_len=mac_len)

    rd = AES.test_decrypt(_decrypt, mode, AES.KeyLength.ALL, resilience=True)
    print(rd.keys())
    console.print_results(rd)
    assert rd.check()
