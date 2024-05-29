"""Wrapper example 1: HMAC interface with PyCryptodome's HMAC-SHA256.

For HMAC wrappers, we need to create a class named CC_HMAC, which must conform to one of
the two protocols described in the documentation.

In this example, we want to implement the HMAC interface, which requires the `digest`
and `verify` methods.
"""

from Crypto.Hash import HMAC, SHA256


class CC_HMAC:
    """Wraps PyCryptodome's HMAC."""

    def digest(self, key: bytes, message: bytes) -> bytes:
        """Returns the MAC tag."""
        # First we create a new instance with the given key and message, while
        # specifying the hash function to use.
        h = HMAC.new(key, message, digestmod=SHA256)
        # Then we simply return the MAC tag.
        return h.digest()

    def verify(self, key: bytes, message: bytes, mac: bytes) -> bool:
        """Checks the MAC tag."""
        # As with digest, we create a new instance.
        h = HMAC.new(key, message, digestmod=SHA256)
        # We wrap the `verify` method in a try/except block, as it raises ValueError
        # when the MAC is invalid, and we want to return a bool instead.
        try:
            h.verify(mac)
            return True
        except ValueError:
            return False
