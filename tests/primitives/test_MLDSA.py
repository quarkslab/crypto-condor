"""Module to test the ML-DSA primitive."""

import random
from pathlib import Path

import pytest

from crypto_condor.primitives import MLDSA
from crypto_condor.primitives.common import Console

console = Console()

# the ref implementation does not perform some of the mandatory input checking
# (such as the value of s1/s2 coefficients)
# some checks are performed by the external function
# where we have to use the internal one
#
# the test functions add the input checking where necessary to catch the
# Wycheproof vectors which would fail, # and enable a success of the test if
# everything else works

# FIPS 204 Table1 : (k, l, eta)
_MLDSA_PARAMS: dict[MLDSA.Paramset, tuple[int, int, int]] = {
    MLDSA.Paramset.ML_DSA_44: (4, 4, 2),
    MLDSA.Paramset.ML_DSA_65: (6, 5, 4),
    MLDSA.Paramset.ML_DSA_87: (8, 7, 2),
}


def _check_poly_eta2(data: bytes) -> bool:
    """Validate a polynomial packed with ETA=2 (3 bits per coefficient).

    Each group of 8 coefficients is packed into 3 bytes. The raw value
    must be <= 2*ETA=4 for the coefficient to be in [-ETA, ETA].
    """
    for i in range(32):
        b0 = data[3 * i]
        b1 = data[3 * i + 1]
        b2 = data[3 * i + 2]
        raw = [
            b0 & 7,
            (b0 >> 3) & 7,
            ((b0 >> 6) | (b1 << 2)) & 7,
            (b1 >> 1) & 7,
            (b1 >> 4) & 7,
            ((b1 >> 7) | (b2 << 1)) & 7,
            (b2 >> 2) & 7,
            (b2 >> 5) & 7,
        ]
        for v in raw:
            if v > 4:
                return False
    return True


def _check_poly_eta4(data: bytes) -> bool:
    """Validate a polynomial packed with ETA=4 (4 bits per coefficient).

    Each byte holds 2 coefficients. The raw value must be <= 2*ETA=8
    for the coefficient to be in [-ETA, ETA].
    """
    for b in data:
        if (b & 0x0F) > 8 or (b >> 4) > 8:
            return False
    return True


def _check_sk(paramset: MLDSA.Paramset, sk: bytes) -> bool:
    """Validate an ML-DSA secret key.

    Checks length, context, and that s1/s2 coefficients are in range.

    Secret key layout:
        rho(32) || K(32) || tr(64) || s1 || s2 || t0
    """
    if len(sk) != paramset.sk_size:
        return False

    k, ell, eta = _MLDSA_PARAMS[paramset]
    offset = 128  # Skip rho(32) + K(32) + tr(64)

    if eta == 2:
        packed = 96   # 256 coefficients * 3 bits / 8
        check = _check_poly_eta2
    else:
        packed = 128  # 256 coefficients * 4 bits / 8
        check = _check_poly_eta4

    # Check s1 (ell polynomials)
    for _ in range(ell):
        if not check(sk[offset : offset + packed]):
            return False
        offset += packed

    # Check s2 (k polynomials)
    for _ in range(k):
        if not check(sk[offset : offset + packed]):
            return False
        offset += packed

    return True


def _check_pk(paramset: MLDSA.Paramset, pk: bytes) -> bool:
    """Validate an ML-DSA public key length."""
    return len(pk) == paramset.pk_size


def _check_ctx(ctx: bytes) -> bool:
    """Validate the context string."""
    return len(ctx) <= 255


@pytest.mark.parametrize("paramset", MLDSA.Paramset)
def test_sign(paramset: MLDSA.Paramset):
    """Tests internal signing function."""

    def _sign(
        sk: bytes, msg: bytes, ctx: bytes, ph: str = ""
    ) -> tuple[bool, bytes]:
        if not _check_sk(paramset, sk) or not _check_ctx(ctx):
            return False, b""
        return True, MLDSA._sign(paramset, sk, msg, ctx)

    rd = MLDSA.test_sign(_sign, paramset, resilience=True)
    assert rd.check()


@pytest.mark.parametrize("paramset", MLDSA.Paramset)
def test_sign_prehash(paramset: MLDSA.Paramset):
    """Tests prehash signing with FIPS 204 vectors."""

    def _sign(
        sk: bytes, msg: bytes, ctx: bytes, ph: str = ""
    ) -> tuple[bool, bytes]:
        if not _check_sk(paramset, sk) or not _check_ctx(ctx):
            return False, b""
        return True, MLDSA._sign_prehash(paramset, sk, msg, ctx, ph)

    rd = MLDSA.test_sign(_sign, paramset, prehash=True, resilience=True)
    assert rd.check()


@pytest.mark.parametrize("paramset", MLDSA.Paramset)
def test_verify(paramset: MLDSA.Paramset):
    """Tests internal verifying function."""

    def _verify(pk: bytes, msg: bytes, sig: bytes, ctx: bytes, ph: str = ""):
        if not _check_pk(paramset, pk) or not _check_ctx(ctx):
            return False
        return MLDSA._verify(paramset, pk, msg, sig, ctx)

    rd = MLDSA.test_verify(_verify, paramset, resilience=True)
    assert rd.check()


@pytest.mark.parametrize("paramset", MLDSA.Paramset)
def test_verify_prehash(paramset: MLDSA.Paramset):
    """Tests prehash verification with FIPS 204 vectors."""

    def _verify(pk: bytes, msg: bytes, sig: bytes, ctx: bytes, ph: str = ""):
        if not _check_pk(paramset, pk) or not _check_ctx(ctx):
            return False
        return MLDSA._verify_prehash(paramset, pk, msg, sig, ctx, ph)

    rd = MLDSA.test_verify(_verify, paramset, prehash=True, resilience=True)
    assert rd.check()


@pytest.mark.parametrize("paramset", MLDSA.Paramset)
def test_sign_deterministic(paramset: MLDSA.Paramset):
    """Tests deterministic signing against FIPS 204 vectors."""

    def _sign(
        sk: bytes, msg: bytes, ctx: bytes, ph: str = ""
    ) -> tuple[bool, bytes]:
        if not _check_sk(paramset, sk) or not _check_ctx(ctx):
            return False, b""
        return True, MLDSA._sign_deterministic(paramset, sk, msg, ctx)

    rd = MLDSA.test_sign_deterministic(_sign, paramset, resilience=True)
    assert rd.check()


@pytest.mark.parametrize("paramset", MLDSA.Paramset)
def test_sign_deterministic_prehash(paramset: MLDSA.Paramset):
    """Tests deterministic prehash signing against FIPS 204 vectors."""

    def _sign(
        sk: bytes, msg: bytes, ctx: bytes, ph: str = ""
    ) -> tuple[bool, bytes]:
        if not _check_sk(paramset, sk) or not _check_ctx(ctx):
            return False, b""
        return True, MLDSA._sign_prehash(paramset, sk, msg, ctx, ph)

    rd = MLDSA.test_sign_deterministic(_sign, paramset, prehash=True, resilience=True)
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
