"""Enums for SLH-DSA."""

import strenum


class Paramset(strenum.StrEnum):
    """SLH-DSA parameter set."""

    SHA2_128S = "SHA2-128s"
    SHAKE_128S = "SHAKE-128s"
    SHA2_128F = "SHA2-128f"
    SHAKE_128F = "SHAKE-128f"
    SHA2_192S = "SHA2-192s"
    SHAKE_192S = "SHAKE-192s"
    SHA2_192F = "SHA2-192f"
    SHAKE_192F = "SHAKE-192f"
    SHA2_256S = "SHA2-256s"
    SHAKE_256S = "SHAKE-256s"
    SHA2_256F = "SHA2-256f"
    SHAKE_256F = "SHAKE-256f"

    def __init__(self, value):
        """Override __init__ to add custom properties."""
        self._value_ = value
        if "128s" in value:
            self._pk_size_ = 32
            self._sk_size_ = 64
            self._sig_size_ = 7856
        elif "128f" in value:
            self._pk_size_ = 32
            self._sk_size_ = 64
            self._sig_size_ = 17088
        elif "192s" in value:
            self._pk_size_ = 48
            self._sk_size_ = 96
            self._sig_size_ = 16224
        elif "192f" in value:
            self._pk_size_ = 48
            self._sk_size_ = 96
            self._sig_size_ = 35664
        elif "256s" in value:
            self._pk_size_ = 64
            self._sk_size_ = 128
            self._sig_size_ = 29792
        else:
            self._pk_size_ = 64
            self._sk_size_ = 128
            self._sig_size_ = 49856

    @property
    def pk_size(self) -> int:
        """Returns the size of the public key in bytes."""
        return self._pk_size_

    @property
    def sk_size(self) -> int:
        """Returns the size of the secret key in bytes."""
        return self._sk_size_

    @property
    def sig_size(self) -> int:
        """Returns the size of the signature in bytes."""
        return self._sig_size_

    @classmethod
    def from_name(cls, pset_hash: str, pset_strength: str):
        """Creates instance from a function name."""
        return cls(f"{pset_hash.upper()}-{pset_strength}")
