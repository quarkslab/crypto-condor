"""Test vectors for SHA."""

import strenum


class Algorithm(strenum.StrEnum):
    """Supported hash algorithms."""

    def __init__(self, value):
        """Override __init__ to add custom properties."""
        self._value_ = value
        match value:
            case "SHA-1":
                self._digest_size_ = 160
            case "SHA-224" | "SHA-512/224" | "SHA3-224":
                self._digest_size_ = 224
            case "SHA-256" | "SHA-512/256" | "SHA3-256":
                self._digest_size_ = 256
            case "SHA-384" | "SHA3-384":
                self._digest_size_ = 384
            case "SHA-512" | "SHA3-512":
                self._digest_size_ = 512

    @property
    def digest_size(self) -> int:
        """The size in bits of the algorithm's digest."""
        return self._digest_size_

    @property
    def file_safe(self) -> str:
        """Returns a version of the name safe for filenames.

        Replaces any forward slashes with dashes.
        """
        return self._value_.replace("/", "-")

    @property
    def sha3(self):
        """True if the algorithm is a SHA-3 algorithm."""
        return self._value_ in {"SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512"}

    @classmethod
    def from_wrapper(cls, parts: list[str]):
        """Returns an instance from a partial wrapper name."""
        if len(parts) == 1:
            return cls(f"SHA-{parts[0]}")
        elif parts[0] == "3":
            return cls(f"SHA3-{parts[1]}")
        elif parts[0] == "512":
            return cls(f"SHA-512/{parts[1]}")
        else:
            raise ValueError(f"Invalid algorithm name {parts}")

    SHA_1 = "SHA-1"
    SHA_224 = "SHA-224"
    SHA_256 = "SHA-256"
    SHA_384 = "SHA-384"
    SHA_512 = "SHA-512"
    SHA_512_224 = "SHA-512/224"
    SHA_512_256 = "SHA-512/256"
    SHA3_224 = "SHA3-224"
    SHA3_256 = "SHA3-256"
    SHA3_384 = "SHA3-384"
    SHA3_512 = "SHA3-512"


class Hash(strenum.StrEnum):
    """A hash function that can be used with HMAC."""

    SHA_1 = "SHA-1"
    SHA_224 = "SHA-224"
    SHA_256 = "SHA-256"
    SHA_384 = "SHA-384"
    SHA_512 = "SHA-512"
    SHA_512_224 = "SHA-512/224"
    SHA_512_256 = "SHA-512/256"
    SHA3_224 = "SHA3-224"
    SHA3_256 = "SHA3-256"
    SHA3_384 = "SHA3-384"
    SHA3_512 = "SHA3-512"

    def __init__(self, value):
        """Override __init__ to add custom properties."""
        self._value_ = value
        match value:
            case "SHA-1":
                self._digest_size_ = 160
            case "SHA-224" | "SHA3-224" | "SHA-512/224":
                self._digest_size_ = 224
            case "SHA-256" | "SHA3-256" | "SHA-512/256":
                self._digest_size_ = 256
            case "SHA-384" | "SHA3-384":
                self._digest_size_ = 384
            case "SHA-512" | "SHA3-512":
                self._digest_size_ = 512

    @property
    def digest_size(self) -> int:
        """Returns the size of the digest in bits."""
        return self._digest_size_

    @property
    def sha3(self):
        """True if the algorithm is a SHA-3 algorithm."""
        return self._value_ in {"SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512"}

    @classmethod
    def from_name(cls, name: str):
        """Returns a new instance from a name.

        Compact names such as sha256, sha3384 (SHA3-384) and sha512224 (SHA-512/224) are
        used for harness function names. This method returns the corresponding instance.

        Raises:
            ValueError:
                If the name is invalid.
        """
        match name:
            case "sha1" | "sha224" | "sha256" | "sha384" | "sha512":
                newname = name.replace("sha", "SHA-")
            case "sha3256" | "sha3384" | "sha3512":
                newname = name.replace("sha3", "SHA3-")
            case "sha512224":
                newname = "SHA-512/224"
            case "sha512256":
                newname = "SHA-512/256"
            case _:
                raise ValueError(f"Invalid hash name {name}")
        if newname not in cls:
            # Use name for the error message as that's what the user wrote.
            raise ValueError(f"{name} is not supported for HMAC")
        return cls(newname)
