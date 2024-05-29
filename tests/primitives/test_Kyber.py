"""Module to test Kyber."""

import pytest

from crypto_condor.primitives import Kyber
from crypto_condor.primitives.common import Console
from crypto_condor.vectors.Kyber import KyberVectors

console = Console()


@pytest.mark.parametrize("parameter_set", Kyber.Paramset)
def test_encapsulate(parameter_set: Kyber.Paramset):
    """Tests encapsulation."""
    vectors = KyberVectors.load(parameter_set)

    for test in vectors.tests:
        ct, ss = Kyber._encapsulate(parameter_set, test.pk)
        res_ss = Kyber._decapsulate(parameter_set, test.sk, ct)
        assert res_ss == ss


@pytest.mark.parametrize("parameter_set", Kyber.Paramset)
def test_decapsulate(parameter_set: Kyber.Paramset):
    """Tests decapsulation."""
    vectors = KyberVectors.load(parameter_set)

    for test in vectors.tests:
        ss = Kyber._decapsulate(parameter_set, test.sk, test.ct)
        assert ss == test.ss


@pytest.mark.parametrize("parameter_set", Kyber.Paramset)
def test_test_encapsulate(parameter_set: Kyber.Paramset):
    """Tests :func:`crypto_condor.primitives.Kyber.test`.

    Only tests an encapsulation function.
    """

    def _encap(pk):
        return Kyber._encapsulate(parameter_set, pk)

    results = Kyber.test_encapsulate(_encap, parameter_set)
    assert results is not None, "results is None"
    console.print_results(results)
    assert results.check()


@pytest.mark.parametrize("parameter_set", Kyber.Paramset)
def test_test_decapsulate(parameter_set: Kyber.Paramset):
    """Tests :func:`crypto_condor.primitives.Kyber.test`.

    Only tests a decapsulation function.
    """

    def _decap(sk, ct):
        return Kyber._decapsulate(parameter_set, sk, ct)

    results = Kyber.test_decapsulate(_decap, parameter_set)
    console.print_results(results)
    assert results.check()
