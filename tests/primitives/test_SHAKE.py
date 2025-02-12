"""Tests for the SHAKE module."""

import pytest
from cryptography.hazmat.primitives import hashes

from crypto_condor.primitives import SHAKE
from crypto_condor.primitives.common import Console

console = Console()


@pytest.mark.parametrize("xof_algorithm", SHAKE.Algorithm)
def test_shake(xof_algorithm: SHAKE.Algorithm):
    """Tests :func:`crypto_condor.primitives.SHAKE.test`.

    Uses :mod:`cryptography.hazmat.primitives.hashes`.
    """

    def _xof(data: bytes, output_length: int = 0):
        """Directly returns the message digest."""
        assert output_length >= 0, "Output len must be positive"
        match xof_algorithm:
            case "SHAKE128":
                if output_length == 0:
                    output_length = 128 // 8
                digest = hashes.Hash(hashes.SHAKE128(output_length))
            case "SHAKE256":
                if output_length == 0:
                    output_length = 256 // 8
                digest = hashes.Hash(hashes.SHAKE256(output_length))
            case _:
                raise ValueError("Unsupported XOF %s" % xof_algorithm)
        digest.update(data)
        return digest.finalize()

    # cryptography's implementation is byte-oriented
    results_dict = SHAKE.test_digest(_xof, xof_algorithm, SHAKE.Orientation.BYTE)
    console.print_results(results_dict)
    assert results_dict.check()
