"""Wrapper example: HMAC_IUF interface with PyCryptodome's HMAC-SHA256.

For HMAC wrappers, we need to create a class named CC_HMAC, which must conform to one of
the two protocols described in the documentation.

In this example, we want to implement the HMAC_IUF interface, which requires four
methods:

- `init`
- `update`
- `digest`
- `verify`
"""

from Crypto.Hash import HMAC, SHA256


class CC_HMAC:
    """Wraps PyCryptodome's HMAC."""

    # We need a class attribute to hold the HMAC instance returned by PyCryptodome.
    _obj: HMAC.HMAC

    # This is a class method as we want to create a new instance of the class when
    # calling this method.
    @classmethod
    def init(cls, key: bytes):
        """Creates a new instance."""
        # Create the instance of CC_HMAC
        h = cls()
        # Create the instance of HMAC and store it in _obj
        h._obj = HMAC.new(key, digestmod=SHA256)
        # Return the instance of CC_HMAC
        return h

    def update(self, data: bytes):
        """Adds the next chunk of data to process."""
        # Use the internal object and update its data.
        self._obj.update(data)

    def final_digest(self) -> bytes:
        """Returns the MAC tag."""
        return self._obj.digest()

    def final_verify(self, mac: bytes) -> bool:
        """Checks the MAC tag."""
        # We wrap the `verify` method in a try/except block, as it raises ValueError
        # when the MAC is invalid, and we want to return a bool instead.
        try:
            self._obj.verify(mac)
            return True
        except ValueError:
            return False
