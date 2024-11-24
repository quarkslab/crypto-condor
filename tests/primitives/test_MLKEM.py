"""Module to test the ML-KEM primitive."""

from pathlib import Path

import pytest

from crypto_condor.primitives import MLKEM
from crypto_condor.primitives.common import Console

console = Console()


@pytest.mark.parametrize("paramset", MLKEM.Paramset)
def test_encaps(paramset: MLKEM.Paramset):
    """Test for :func:`crypto_condor.primitives.MLKEM.test_encaps`."""

    def _encaps(pk: bytes) -> tuple[bytes, bytes]:
        return MLKEM._encaps(paramset, pk)

    rd = MLKEM.test_encaps(_encaps, paramset)
    assert rd is not None
    assert rd.check()


@pytest.mark.parametrize("paramset", MLKEM.Paramset)
def test_decaps(paramset: MLKEM.Paramset):
    """Test for :func:`crypto_condor.primitives.MLKEM.test_decaps`."""

    def _decaps(sk: bytes, ct: bytes) -> bytes:
        return MLKEM._decaps(paramset, sk, ct)

    rd = MLKEM.test_decaps(_decaps, paramset)
    assert rd.check()


@pytest.mark.parametrize("paramset", MLKEM.Paramset)
def test_output_encaps(paramset: MLKEM.Paramset, tmp_path: Path):
    """Test for :func:`crypto_condor.primitives.MLKEM.test_output_encaps`."""
    output = tmp_path / f"{str(paramset)}.txt"
    lines = list()
    for _ in range(50):
        pk, sk = MLKEM._keygen(paramset)
        ct, ss = MLKEM._encaps(paramset, pk)
        lines.append(f"{pk.hex()}/{sk.hex()}/{ct.hex()}/{ss.hex()}")
    output.write_text("\n".join(lines))

    rd = MLKEM.test_output_encaps(output, paramset)
    assert rd.check()
