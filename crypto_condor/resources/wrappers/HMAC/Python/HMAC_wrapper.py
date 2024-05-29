"""Wrapper for HMAC implementations.

Usage:
    This wrapper contains two interfaces, HMAC and HMAC_IUF. Refer to the documentation
    for a description of these interfaces and fill the corresponding class.

    crypto-condor imports this wrapper and looks for a class named CC_HMAC. To test the
    implementation you have filled, rename the corresponding class to CC_HMAC. Then,
    run:

    crypto-condor-cli test wrapper HMAC Python <hash function>

    To see the possible options, run:

    crypto-condor-cli test wrapper HMAC --help
"""


class HMAC:
    """Implements the HMAC interface."""

    def digest(self, key: bytes, message: bytes) -> bytes:
        """Returns the MAC tag."""
        raise NotImplementedError

    def verify(self, key: bytes, message: bytes, mac: bytes) -> bool:
        """Verifies the MAC tag."""
        raise NotImplementedError


class HMAC_IUF:
    """Implements the HMAC_IUF interface."""

    @classmethod
    def init(cls, key: bytes):
        """Returns a new instance of the class."""
        raise NotImplementedError

    def update(self, data: bytes):
        """Adds a new chunk of data to process."""
        raise NotImplementedError

    def final_digest(self) -> bytes:
        """Finalizes the processing and returns the MAC tag."""
        raise NotImplementedError

    def final_verify(self, mac: bytes) -> bytes:
        """Finalizes the processing and returns True if the MAC tag is valid."""
        raise NotImplementedError
