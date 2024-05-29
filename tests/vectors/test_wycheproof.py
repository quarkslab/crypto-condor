"""Module to test the integration with Wycheproof test vectors."""

import pytest

from crypto_condor.vectors.AES import AesVectors, Mode


@pytest.mark.parametrize("mode", [Mode.GCM, Mode.CCM, Mode.CBC_PKCS7])
def test_aes_vectors(mode: Mode):
    """Tests loading Wycheproof AES vectors."""
    vectors = AesVectors.load(mode)
    assert vectors.wycheproof is not None


@pytest.mark.parametrize("mode", [Mode.ECB, Mode.CBC, Mode.CTR, Mode.CFB])
def test_aes_unsupported(mode: Mode):
    """Tests loading an unsupported mode of operation."""
    vectors = AesVectors.load(mode)
    assert vectors.wycheproof is None
