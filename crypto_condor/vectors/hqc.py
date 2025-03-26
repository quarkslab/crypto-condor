"""Enums for HQC."""

import strenum


class Paramset(strenum.StrEnum):
    """HQC parameter sets."""

    HQC128 = "HQC-128"
    HQC192 = "HQC-192"
    HQC256 = "HQC-256"

    def __new__(cls, value):
        """Override __new__ to add custom properties."""
        member = str.__new__(cls, value)
        member._value_ = value
        match value:
            case "HQC-128":
                member._pk_size_ = 2249
                member._sk_size_ = 56
                member._ct_size_ = 4497
                member._ss_size_ = 64
            case "HQC-192":
                member._pk_size_ = 4522
                member._sk_size_ = 64
                member._ct_size_ = 9042
                member._ss_size_ = 64
            case "HQC-256":
                member._pk_size_ = 7245
                member._sk_size_ = 72
                member._ct_size_ = 14485
                member._ss_size_ = 64
        return member

    @property
    def pk_size(self):
        """The size of the public key in bytes."""
        return self._pk_size_

    @property
    def sk_size(self):
        """The size of the secret key in bytes."""
        return self._sk_size_

    @property
    def ct_size(self):
        """The size of the ciphertext in bytes."""
        return self._ct_size_

    @property
    def ss_size(self):
        """The size of the shared secret in bytes."""
        return self._ss_size_
