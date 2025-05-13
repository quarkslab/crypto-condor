"""Tests for :mod:`crypto_condor.primitives.HMAC`."""

import pytest

from crypto_condor.primitives import HMAC

from ..utils.hmac import generate_hmac_output


@pytest.mark.parametrize(("algo"), HMAC.Hash)
def test_output(algo: HMAC.Hash, tmp_path):
    """Tests :func:`crypto_condor.primitives.HMAC.test_output_digest`."""
    output = generate_hmac_output(str(algo), algo.digest_size // 8, True)
    output_file = tmp_path / f"hmac_{str(algo)}.txt"
    output_file.write_text(output)

    rd = HMAC.test_output_digest(output_file, algo)
    assert rd.check(fail_if_empty=True)


@pytest.mark.parametrize(("algo"), HMAC.Hash)
def test_output_invalid(algo: HMAC.Hash, tmp_path):
    """Tests :func:`crypto_condor.primitives.HMAC.test_output_digest`."""
    output = generate_hmac_output(str(algo), algo.digest_size // 8, False)
    output_file = tmp_path / f"hmac_{str(algo)}_invalid.txt"
    output_file.write_text(output)

    rd = HMAC.test_output_digest(output_file, algo)
    assert not rd.check()
