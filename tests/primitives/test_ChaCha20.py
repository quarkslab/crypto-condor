"""Module to test the AES primitive."""

import pytest

from crypto_condor.primitives import ChaCha20


@pytest.mark.parametrize("mode", ChaCha20.Mode)
def test_mode(mode):
    """Tests the correctness of the internal implementation."""

    # Define inner functions to set the correct mode.
    def _encrypt(key, plaintext, nonce, *, init_counter=0, aad=None):
        return ChaCha20._encrypt(
            mode, key, plaintext, nonce, aad=aad, init_counter=init_counter
        )

    def _decrypt(key, ciphertext, nonce, *, init_counter=0, mac=None, aad=None):
        return ChaCha20._decrypt(
            mode, key, ciphertext, nonce, mac=mac, aad=aad, init_counter=init_counter
        )

    result_group = ChaCha20.test(_encrypt, _decrypt, mode)
    assert result_group.check(), str(result_group)
