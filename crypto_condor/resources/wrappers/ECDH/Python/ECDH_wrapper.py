"""Wrapper for ECDH implementations.

Usage:
    This wrapper contains one class that implements the ECDH protocol described in the
    documentation. Fill the methods corresponding to the test vectors you want to use.
    For compliance, use NIST vectors.

    crypto-condor imports this wrapper and looks for a class named CC_ECDH. If it
    exists, it runs the methods of the class with the corresponding test vectors. You
    can leave the NotImplementedError exception for a method you do not want to test, it
    will be caught by crypto-condor and skip that test.

    When the wrapper is filled, run it with the CLI:

    crypto-condor-cli test wrapper ECDH <curve>

    To list the possible options, run:

    crypto-condor-cli test wrapper ECDH --help
"""


class CC_ECDH:
    """Implements the crypto_condor.primitives.ECDH.ECDH protocol."""

    def exchange_nist(
        self, secret: int, pub_x: int, pub_y: int, pub_key: bytes
    ) -> bytes:
        """ECDH exchange with NIST vectors."""
        raise NotImplementedError

    def exchange_wycheproof(self, secret: int, pub_key: bytes) -> bytes:
        """ECDH exchange with Wycheproof vectors."""
        raise NotImplementedError
