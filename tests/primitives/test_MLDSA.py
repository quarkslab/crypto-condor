"""Module to test the ML-DSA primitive."""

import random
from pathlib import Path

import pytest

from crypto_condor.primitives import MLDSA
from crypto_condor.primitives.common import Console

console = Console()


@pytest.mark.parametrize("paramset", MLDSA.Paramset)
def test_sign(paramset: MLDSA.Paramset):
    """Tests internal signing function."""

    def _sign(sk: bytes, msg: bytes, ctx: bytes) -> bytes:
        return MLDSA._sign(paramset, sk, msg, ctx)

    rd = MLDSA.test_sign(_sign, paramset)
    assert rd.check()


@pytest.mark.parametrize("paramset", MLDSA.Paramset)
def test_verify(paramset: MLDSA.Paramset):
    """Tests internal verifying function."""

    def _verify(pk: bytes, msg: bytes, sig: bytes, ctx: bytes):
        return MLDSA._verify(paramset, pk, msg, sig, ctx)

    rd = MLDSA.test_verify(_verify, paramset)
    assert rd.check()


@pytest.mark.parametrize("paramset", MLDSA.Paramset)
def test_output_encaps(paramset: MLDSA.Paramset, tmp_path: Path):
    """Test for :func:`crypto_condor.primitives.MLDSA.test_output_encaps`."""
    output = tmp_path / f"{str(paramset)}.txt"
    lines = list()
    for _ in range(50):
        pk, sk = MLDSA._keygen(paramset)
        msglen = random.randint(128, 1024)
        # ctx is a byte string of 255 or fewer bytes
        ctxlen = random.randint(16, 255)
        msg = random.randbytes(msglen)
        ctx = random.randbytes(ctxlen)
        sig = MLDSA._sign(paramset, sk, msg, ctx)
        lines.append(f"{pk.hex()}/{msg.hex()}/{sig.hex()}/{ctx.hex()}")
    for _ in range(50):
        pk, sk = MLDSA._keygen(paramset)
        msglen = random.randint(128, 1024)
        msg = random.randbytes(msglen)
        sig = MLDSA._sign(paramset, sk, msg, b"")
        lines.append(f"{pk.hex()}/{msg.hex()}/{sig.hex()}/")
    output.write_text("\n".join(lines))

    rd = MLDSA.test_output_sign(output, paramset)
    assert rd.check()
