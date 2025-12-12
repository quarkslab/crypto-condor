"""Enums for ECDSA."""

from crypto_condor.common import CommonCurve, CommonHash


class Curve(CommonCurve):
    """The supported elliptic curves."""

    P224 = "P-224"
    P256 = "P-256"
    P384 = "P-384"
    P521 = "P-521"
    B283 = "B-283"
    B409 = "B-409"
    B571 = "B-571"
    SECP256K1 = "secp256k1"
    BRAINPOOLP256R1 = "brainpoolP256r1"
    BRAINPOOLP384R1 = "brainpoolP384r1"
    BRAINPOOLP512R1 = "brainpoolP512r1"

    def get_curve_instance(self):
        """Returns an instance of the corresponding curve.

        Curves come from the :mod:`cryptography.hazmat.primitives.asymmetric.ec` module.
        """
        from cryptography.hazmat.primitives.asymmetric import ec

        match self:
            case Curve.P224:
                return ec.SECP224R1()
            case Curve.P256:
                return ec.SECP256R1()
            case Curve.P384:
                return ec.SECP384R1()
            case Curve.P521:
                return ec.SECP521R1()
            case Curve.B283:
                return ec.SECT283R1()
            case Curve.B409:
                return ec.SECT409R1()
            case Curve.B571:
                return ec.SECT571R1()
            case Curve.SECP256K1:
                return ec.SECP256K1()
            case Curve.BRAINPOOLP256R1:
                return ec.BrainpoolP256R1()
            case Curve.BRAINPOOLP384R1:
                return ec.BrainpoolP384R1()
            case Curve.BRAINPOOLP512R1:
                return ec.BrainpoolP512R1()
            case _:
                raise ValueError(f"Unexpected curve: {str(self)}")


class Hash(CommonHash):
    """The supported hash functions."""

    SHA224 = "SHA-224"
    SHA256 = "SHA-256"
    SHA384 = "SHA-384"
    SHA512 = "SHA-512"
    SHA512_224 = "SHA-512/224"
    SHA512_256 = "SHA-512/256"
    SHA3_224 = "SHA3-224"
    SHA3_256 = "SHA3-256"
    SHA3_384 = "SHA3-384"
    SHA3_512 = "SHA3-512"

    def get_hash_instance(self):
        """Returns an instance of the corresponding hash function.

        Hash functions come from :mod:`cryptography.hazmat.primitives.hashes` module.
        """
        from cryptography.hazmat.primitives import hashes

        match self:
            case Hash.SHA224:
                return hashes.SHA224()
            case Hash.SHA256:
                return hashes.SHA256()
            case Hash.SHA384:
                return hashes.SHA384()
            case Hash.SHA512:
                return hashes.SHA512()
            case Hash.SHA512_224:
                return hashes.SHA512_224()
            case Hash.SHA512_256:
                return hashes.SHA512_256()
            case Hash.SHA3_224:
                return hashes.SHA3_224()
            case Hash.SHA3_256:
                return hashes.SHA3_256()
            case Hash.SHA3_384:
                return hashes.SHA3_384()
            case Hash.SHA3_512:
                return hashes.SHA3_512()
            case _:
                raise ValueError(f"Unexpected hash: {str(self)}")
