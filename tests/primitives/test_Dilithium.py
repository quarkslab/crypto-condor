"""Module to test Dilithium."""

import pytest

from crypto_condor.primitives import Dilithium
from crypto_condor.primitives.common import Console

console = Console()


@pytest.mark.parametrize("parameter_set", Dilithium.Paramset)
def test_sign(parameter_set: Dilithium.Paramset):
    """Tests internal signing function."""
    vectors = Dilithium.DilithiumVectors.load(parameter_set)
    for vector in vectors.tests:
        sm = Dilithium._sign(parameter_set, vector.sk, vector.msg)
        assert sm == vector.sm, f"Test {vector.count} failed"


@pytest.mark.parametrize("parameter_set", Dilithium.Paramset)
def test_verify(parameter_set: Dilithium.Paramset):
    """Tests internal verifying function."""
    vectors = Dilithium.DilithiumVectors.load(parameter_set)
    for vector in vectors.tests:
        assert Dilithium._verify(parameter_set, vector.pk, vector.sm)


@pytest.mark.parametrize("parameter_set", Dilithium.Paramset)
def test_test_sign(parameter_set: Dilithium.Paramset):
    """Tests :func:`crypto_condor.primitives.Dilithium.test`.

    Only tests signature generation.
    """

    def _sign(sk, msg):
        return Dilithium._sign(parameter_set, sk, msg)

    results = Dilithium.test_sign(_sign, parameter_set)
    console.print_results(results)
    assert results.check()


@pytest.mark.parametrize("parameter_set", Dilithium.Paramset)
def test_test_verify(parameter_set: Dilithium.Paramset):
    """Tests :func:`crypto_condor.primitives.Dilithium.test`.

    Only tests signature verification.
    """

    def _verify(pk, sig, msg):
        return Dilithium._verify(parameter_set, pk, sig, msg)

    results = Dilithium.test_verify(_verify, parameter_set)
    console.print_results(results)
    assert results.check()
