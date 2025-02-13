"""Module to test ECDSA."""

from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from crypto_condor.primitives import ECDSA
from crypto_condor.primitives.common import Console
from crypto_condor.vectors.ECDSA import EcdsaSigVerVectors

console = Console()


@pytest.mark.parametrize(
    "curve,hash_function",
    [
        (ECDSA.Curve.SECP192R1, ECDSA.Hash.SHA_256),
        (ECDSA.Curve.SECP224R1, ECDSA.Hash.SHA_256),
        (ECDSA.Curve.SECP256R1, ECDSA.Hash.SHA_256),
        (ECDSA.Curve.SECP256K1, ECDSA.Hash.SHA_256),
        (ECDSA.Curve.BRAINPOOLP256R1, ECDSA.Hash.SHA_256),
    ],
)
def test_verify_file(curve: ECDSA.Curve, hash_function: ECDSA.Hash, tmp_path: Path):
    """Tests :func:`crypto_condor.primitives.ECDSA.verify_file`.

    Since ``verify_file`` expects a file with only presumed-valid signatures,
    we parse the vectors and separate the valid from the invalid ones.
    """
    vectors = EcdsaSigVerVectors.load(curve, hash_function, compliance=False)

    # Separate the test vectors into two categories.
    valid = list()
    invalid = list()

    for test_group in vectors.wycheproof["testGroups"]:
        key = test_group["keyDer"]
        for test in test_group["tests"]:
            message = test["msg"]
            signature = test["sig"]
            line = f"{key}/{message}/{signature}"
            if test["result"] == "valid":
                valid.append(line)
            elif test["result"] == "invalid":
                invalid.append(line)

    valid_file = tmp_path / f"ecdsa_{str(curve)}_{str(hash_function)}_valid.txt"
    invalid_file = tmp_path / f"ecdsa_{str(curve)}_{str(hash_function)}_invalid.txt"

    # Run valid test vectors.
    text = "\n".join(valid)
    valid_file.write_text(text)
    results = ECDSA.verify_file(
        str(valid_file), ECDSA.PubKeyEncoding.DER, hash_function
    )

    console.print_results(results)
    passed = results.valid.passed
    assert passed == len(valid), f"Expected {len(valid)} passed tests, {passed} passed"
    assert results.valid.failed == 0, "There are failed tests"

    # Run invalid test vectors.
    text = "\n".join(invalid)
    invalid_file.write_text(text)
    results = ECDSA.verify_file(
        str(invalid_file), ECDSA.PubKeyEncoding.DER, hash_function
    )

    console.print_results(results)
    failed = results.valid.failed
    assert failed == len(invalid), (
        f"Expected {len(invalid)} failed invalid tests, {failed} failed"
    )
    assert results.valid.passed == 0, "There are passed invalid tests"


@pytest.mark.parametrize(
    "curve_name, hash_name, nist, wycheproof",
    [
        ("secp192r1", "sha256", True, True),
        ("secp224r1", "sha256", True, True),
        ("secp256r1", "sha256", True, True),
        ("secp256k1", "sha256", False, True),
        ("brainpoolP256r1", "sha256", False, True),
    ],
)
def test_verify(curve_name: str, hash_name: str, nist: bool, wycheproof: bool):
    """Tests :meth:`crypto_condor.primitives.ECDSA.test_verify`.

    Args:
        curve_name: Name of the curve to test.
        hash_name: Name of the hash function to test.
        nist: Whether results from NIST test vectors are expected.
        wycheproof: Whether results from Wycheproof test vectors are expected.
    """
    curve = ECDSA.Curve.from_name(curve_name)
    hash_function = ECDSA.Hash.from_name(hash_name)

    def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Lower-order function to wrap :class:`ECDSA`'s `verify`."""
        return ECDSA._verify(public_key, hash_function, message, signature)

    def _verify_uncompressed(
        public_key: bytes, message: bytes, signature: bytes
    ) -> bool:
        pk = ec.EllipticCurvePublicKey.from_encoded_point(
            curve.get_curve_instance(), public_key
        )
        try:
            pk.verify(signature, message, ec.ECDSA(hash_function.get_hash_instance()))
            return True
        except InvalidSignature:
            return False

    results = ECDSA.test_verify(verify, curve, hash_function, ECDSA.PubKeyEncoding.DER)
    if nist:
        assert results.get("nist", None) is not None
        console.print_results(results["nist"])
        assert results["nist"].check()
    if wycheproof:
        assert results.get("wycheproof", None) is not None
        console.print_results(results["wycheproof"])
        assert results["wycheproof"].check()

    results = ECDSA.test_verify(
        _verify_uncompressed, curve, hash_function, ECDSA.PubKeyEncoding.UNCOMPRESSED
    )
    if nist:
        assert results.get("nist", None) is not None
        console.print_results(results["nist"])
        assert results["nist"].check()
    if wycheproof:
        assert results.get("wycheproof", None) is not None
        console.print_results(results["wycheproof"])
        assert results["wycheproof"].check()


@pytest.mark.parametrize(
    "curve_name, hash_name",
    [
        ("secp192r1", "sha256"),
        ("secp224r1", "sha256"),
        ("secp256r1", "sha256"),
        ("secp256k1", "sha256"),
        ("brainpoolP256r1", "sha256"),
    ],
)
def test_verify_prehashed(curve_name: str, hash_name: str):
    """Tests :meth:`crypto_condor.primitives.ECDSA.test_verify` with prehashed messages."""  # noqa: E501
    curve = ECDSA.Curve.from_name(curve_name)
    hash_function = ECDSA.Hash.from_name(hash_name)

    def _verify(public_key: bytes, message: bytes, signature: bytes):
        return ECDSA._verify(
            public_key, hash_function, message, signature, pre_hashed=True
        )

    group = ECDSA.test_verify(
        _verify, curve, hash_function, ECDSA.PubKeyEncoding.DER, pre_hashed=True
    )
    if group.get("nist", None) is not None:
        assert group["nist"].check()
    if group.get("wycheproof", None) is not None:
        assert group["wycheproof"].check()


@pytest.mark.parametrize(
    "curve_name, hash_name",
    [
        ("secp224r1", "sha256"),
        ("secp256r1", "sha256"),
        ("secp384r1", "sha256"),
        ("secp521r1", "sha256"),
    ],
)
def test_sign(curve_name: str, hash_name: str):
    """Tests :func:`crypto_condor.primitives.ECDSA.test_sign`.

    Uses :mod:`cryptography`'s implementation to sign messages.
    """
    curve = ECDSA.Curve.from_name(curve_name)
    hash_function = ECDSA.Hash.from_name(hash_name)

    def _sign(private_key: bytes, message: bytes) -> bytes:
        loaded_key = serialization.load_der_private_key(private_key, None)
        if not isinstance(loaded_key, ec.EllipticCurvePrivateKey):
            raise ValueError("Loaded key is not an elliptic curve private key.")
        signature = loaded_key.sign(
            message, ec.ECDSA(hash_function.get_hash_instance())
        )
        return signature

    results = ECDSA.test_sign(_sign, curve, hash_function, ECDSA.KeyEncoding.DER)
    assert results is not None, "No results"
    console.print_results(results)
    assert results.check()


@pytest.mark.parametrize(
    "curve_name, hash_name",
    [
        ("secp224r1", "sha256"),
        ("secp256r1", "sha256"),
        ("secp384r1", "sha256"),
        ("secp521r1", "sha256"),
    ],
)
def test_sign_prehashed(curve_name: str, hash_name: str):
    """Tests :meth:`crypto_condor.primitives.ECDSA.test_sign.

    Uses pre-hashed messages and DER encoding.
    """
    curve = ECDSA.Curve.from_name(curve_name)
    hash_function = ECDSA.Hash.from_name(hash_name)

    def _sign(private_key: bytes, message: bytes) -> bytes:
        loaded_key = serialization.load_der_private_key(private_key, None)
        if not isinstance(loaded_key, ec.EllipticCurvePrivateKey):
            raise ValueError("Loaded key is not an elliptic curve private key.")
        signature = loaded_key.sign(
            message, ec.ECDSA(utils.Prehashed(hash_function.get_hash_instance()))
        )
        return signature

    results = ECDSA.test_sign(
        _sign, curve, hash_function, ECDSA.KeyEncoding.DER, pre_hashed=True
    )
    assert results is not None, "No results"
    console.print_results(results)
    assert results.check()


# @pytest.mark.xfail(reason="KeyGen arbitrarily fails TestU01")
@pytest.mark.parametrize(
    "curve",
    [
        ECDSA.Curve.SECP224R1,
        ECDSA.Curve.SECP256R1,
        ECDSA.Curve.SECP384R1,
        ECDSA.Curve.SECP521R1,
        ECDSA.Curve.SECT283R1,
        ECDSA.Curve.SECT409R1,
        ECDSA.Curve.SECT571R1,
    ],
)
def test_key_pair(curve: ECDSA.Curve):
    """Tests :func:`crypto_condor.primitives.ECDSA.test_key_pair`.

    Uses :mod:`cryptography` to generate the keys.
    """

    def _generate_key_pair() -> tuple[int, int, int]:
        key = ec.generate_private_key(curve.get_curve_instance())
        d = key.private_numbers().private_value
        public_key = key.public_key()
        qx = public_key.public_numbers().x
        qy = public_key.public_numbers().y
        return (d, qx, qy)

    group = ECDSA.test_key_pair_gen(_generate_key_pair, curve)
    assert group.get("keygen", None) is not None, "No keygen results"
    console.print_results(group["keygen"])
    assert group["keygen"].check()

    assert group.get("testu01", None) is not None, "No TestU01 results"
    console.print_results(group["testu01"])
    assert group["keygen"].check()


@pytest.mark.xfail(reason="KeyGen arbitrarily fails TestU01")
@pytest.mark.parametrize(
    "curve_name",
    ["p224", "p256", "p384", "p521"],
)
def test_key_pair_pycryptodome(curve_name: str):
    """Tests :func:`crypto_condor.primitives.ECDSA.test_key_pair`.

    Uses :mod:`pycryptodome` to generate the keys. We only test the P-curves, as
    pycryptodome doesn't support the NIST binary curves.
    """
    curve = ECDSA.Curve.from_name(curve_name)

    def _generate_key_pair() -> tuple[int, int, int]:
        from Crypto.PublicKey import ECC

        key = ECC.generate(curve=curve_name)
        return (int(key.d), key.pointQ.x, key.pointQ.y)

    group = ECDSA.test_key_pair_gen(_generate_key_pair, curve)
    assert group.check()


@pytest.mark.parametrize(
    "curve_name, hash_name",
    [
        ("secp224r1", "sha256"),
        ("secp256r1", "sha256"),
        ("secp384r1", "sha256"),
        ("secp521r1", "sha256"),
    ],
)
def test_sign_then_verify(curve_name: str, hash_name: str):
    """Tests :func:`crypto_condor.primitives.ECDSA.test_sign_then_verify`.

    Uses :mod:`cryptography`'s implementation to sign messages.
    """
    curve = ECDSA.Curve.from_name(curve_name)
    hash_function = ECDSA.Hash.from_name(hash_name)

    def _sign(private_key: bytes, message: bytes) -> bytes:
        loaded_key = serialization.load_der_private_key(private_key, None)
        if not isinstance(loaded_key, ec.EllipticCurvePrivateKey):
            raise ValueError("Loaded key is not an elliptic curve private key.")
        signature = loaded_key.sign(
            message, ec.ECDSA(hash_function.get_hash_instance())
        )
        return signature

    def _verify(public_key: bytes, message: bytes, signature: bytes):
        return ECDSA._verify(public_key, hash_function, message, signature)

    results = ECDSA.test_sign_then_verify(
        _sign,
        _verify,
        curve,
        ECDSA.KeyEncoding.DER,
        ECDSA.PubKeyEncoding.DER,
    )
    console.print_results(results)
    assert results.check()
