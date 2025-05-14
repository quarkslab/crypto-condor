"""Utils for ECDH tests."""

import random

from crypto_condor.primitives import ECDH


def generate_ecdh_output(curve: ECDH.Curve, valid: bool) -> str:
    """Generates output data for ECDH.

    Args:
        curve:
            The elliptic curve to use.
        valid:
            Whether the output should be a valid shared secret or not.

    Returns:
        A string of correctly formatted output.
    """
    all_vectors = ECDH._load_vectors(curve, ECDH.PubKeyType.X509, False, True)

    output = f"# ECDH valid output for {str(curve)}\n"

    for vectors in all_vectors:
        if vectors.source != "Wycheproof":
            continue
        for test in vectors.tests:
            if valid and test.type != "valid":
                continue
            n = len(test.ss)
            if valid:
                output += f"{test.d.hex()}/{test.peer_x509.hex()}/{test.ss.hex()}\n"
            else:
                output += (
                    f"{test.d.hex()}/{test.peer_x509.hex()}/{random.randbytes(n).hex()}"
                )

    return output
