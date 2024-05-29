"""Module to test the AES primitive."""

import pytest

from crypto_condor.primitives import AES
from crypto_condor.primitives.common import Console

console = Console()


@pytest.mark.parametrize("mode", AES.Mode)
def test_mode(mode: AES.Mode):
    """Tests the correctness of the internal implementation."""

    # Define inner functions to set the correct mode.
    def _encrypt(key, pt, *, iv=None, aad=None, mac_len=0):
        return AES._encrypt(mode, key, pt, iv=iv, aad=aad, mac_len=mac_len)

    def _decrypt(
        key, ct, *, iv=None, segment_size=0, aad=None, mac=None, mac_len=0, tag=None
    ):
        return AES._decrypt(
            mode,
            key,
            ct,
            iv=iv,
            aad=aad,
            mac=mac,
            mac_len=mac_len,
        )

    results_dict = AES.test(_encrypt, _decrypt, mode, AES.KeyLength.ALL)
    console.print_results(results_dict)
    assert results_dict.check()
