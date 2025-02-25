"""Enums for ECDH."""

import strenum


class Curve(strenum.StrEnum):
    """Elliptic curves supported for ECDH."""

    P192 = "P-192"
    P224 = "P-224"
    P256 = "P-256"
    P384 = "P-384"
    P521 = "P-521"
    K163 = "K-163"
    K233 = "K-233"
    K283 = "K-283"
    K409 = "K-409"
    K571 = "K-571"
    B163 = "B-163"
    B233 = "B-233"
    B283 = "B-283"
    B409 = "B-409"
    B571 = "B-571"
    BRAINPOOLP224R1 = "brainpoolP224r1"
    BRAINPOOLP256R1 = "brainpoolP256r1"
    BRAINPOOLP320R1 = "brainpoolP320r1"
    BRAINPOOLP384R1 = "brainpoolP384r1"
    BRAINPOOLP512R1 = "brainpoolP512r1"
    SECP256K1 = "secp256k1"

    @classmethod
    def from_name(cls, name: str):
        """Gets Curve instance from the name of the curve.

        Intended to be used by the wrappers, as hyphens are not allowed in function
        names, so for example P256 is the P-256 curve.
        """
        # First we try to simply get the enum as usual. If it fails, we try with the
        # wrapper/harness version of the name (no hyphens), while being permissive about
        # the case.
        try:
            curve = cls(name)
        except ValueError:
            pass
        else:
            return curve

        name = name.upper()
        match name:
            case "P192" | "P224" | "P256" | "P384" | "P521":
                name = name.replace("P", "P-")
            case "K163" | "K233" | "K283" | "K409" | "K571":
                name = name.replace("K", "K-")
            case "B163" | "B233" | "B283" | "B409" | "B571":
                name = name.replace("B", "B-")
            case (
                "BRAINPOOLP224R1"
                | "BRAINPOOLP256R1"
                | "BRAINPOOLP320R1"
                | "BRAINPOOLP384R1"
                | "BRAINPOOLP512R1"
            ):
                name = name.replace("BRAINPOOL", "brainpool").replace("R", "r")
            case "SECP256K1":
                name = name.lower()
            case _:
                raise ValueError(f"Invalid curve name '{name}'")
        return cls(name)

    def get_ec_name(self) -> str:
        """Gets the curve name for cryptography's ``ec`` module.

        This method is intended for test vectors that provide the public key as
        coordinates, and thus require converting them to a public key or encoded point.

        Returns:
            The curve name.
        """
        name = str(self)
        match name[:2]:
            case "P-":
                return f"SECP{name[2:]}R1"
            case "K-":
                return f"SECT{name[2:]}K1"
            case "B-":
                if name == "B-163":
                    return "SECT163R2"
                return f"SECT{name[2:]}R1"
            case "br":
                return name.upper()
            case "se":
                return name
            case _:
                raise ValueError(f"Invalid curve {name}")
