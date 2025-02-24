"""Script to parse ECDH vectors.

.. caution::
    This module is intended for developers of this tool, as it's only used for
    testing and packaging, has hard-coded filenames, and uses relative paths.
"""

import json
from collections import defaultdict
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from crypto_condor.vectors._ecdh.ecdh_pb2 import EcdhVectors
from crypto_condor.vectors.ecdh import Curve

VECTORS_DIR = Path("crypto_condor/vectors/_ecdh")


def parse_cavp() -> None:
    """Parses NIST CAVP test vectors."""
    file = VECTORS_DIR / "cavp/KAS_ECC_CDH_PrimitiveTest.txt"
    data = file.read_text()
    blocks = [block.strip() for block in data.split("\n\n")]

    # Initialize a "null" vectors instance to distinguish when we already have a real
    # instance.
    vectors: EcdhVectors | None = None
    curve = ""

    for block in blocks:
        if not block or block.startswith("#"):
            continue

        # Curve sections start with e.g. [P-192]
        if block.startswith("["):
            # Determine the curve name
            curve = block.lstrip("[").rstrip("]")
            ec_curve_name = Curve(curve).get_ec_name()
            assert ec_curve_name is not None
            # If we already have an instance, commit it.
            if vectors is not None:
                out = (
                    VECTORS_DIR
                    / "pb2"
                    / f"ecdh_cavp_{vectors.curve}_{vectors.public_type}.pb2"
                )
                out.write_bytes(vectors.SerializeToString())
            # So we initialize a new instance of vectors.
            vectors = EcdhVectors(
                source="NIST CAVP",
                source_desc="Compliance test vectors.",
                source_url="https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Component-Testing#ECCCDH",
                compliance=True,
                curve=curve,
                # NIST vectors use coordinates for the peer's public key. We transform
                # them to an ASN encoded point.
                public_type="point",
            )
            # Nothing more to do with this block.
            continue

        # We should have a valid instance of vectors.
        assert vectors is not None, "vectors is None, missed instantiation"

        # If we reached this point, the block should be test vector data.
        test = vectors.tests.add()
        # We can init fixed values that are not included in the file.
        test.type = "valid"

        qx, qy = 0, 0
        for line in block.split("\n"):
            key, value = line.split(" = ")
            match key:
                case "COUNT":
                    # Since there's only one section per curve, and COUNT is per
                    # section, we can use it as ID.
                    test.id = int(value)
                case "QCAVSx":
                    qx = int(value, 16)
                case "QCAVSy":
                    qy = int(value, 16)
                case "dIUT":
                    test.d = bytes.fromhex(value)
                case "ZIUT":
                    test.ss = bytes.fromhex(value)
                case "QIUTx" | "QIUTy":
                    # We don't need our public coordinates.
                    continue
                case _:
                    raise ValueError(f"Unknown key '{key}'")

        ec_curve = getattr(ec, ec_curve_name)
        numbers = ec.EllipticCurvePublicNumbers(qx, qy, ec_curve())
        test.peer_point = numbers.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )

    # Commit last vectors.
    assert vectors is not None, "vectors is None, missed loop"
    out = VECTORS_DIR / "pb2" / f"ecdh_cavp_{vectors.curve}_{vectors.public_type}.pb2"
    out.write_bytes(vectors.SerializeToString())


def wp_curve_to_cc(curve: str) -> str:
    """Normalize Wycheproof curve names to ECDH.Curve names."""
    # No short name for brainpool curves so we use it as is.
    if curve.startswith("brainpool"):
        return curve
    # Same goes for this one.
    if curve == "secp256k1":
        return curve
    # Otherwise split the curve name into three parts.
    match (curve[0:4], curve[4:7], curve[7:]):
        case ["secp", size, "r1"]:
            return f"P-{size}"
        case ["sect", size, "r1"]:
            return f"B-{size}"
        case ["sect", size, "k1"]:
            return f"K-{size}"
        case _:
            raise ValueError("Unexpected curve %s" % curve)


def _parse_wycheproof_file(src: Path) -> None:
    """Parses a Wycheproof test vectors file.

    Args:
        src: The source file.
    """
    with src.open("r") as fp:
        data = json.load(fp)

    vectors = EcdhVectors(
        source="Wycheproof",
        source_desc=" ".join(data["header"]),
        source_url=(
            f"https://github.com/C2SP/wycheproof/tree/master/testvectors/{src}"
        ),
        compliance=False,
        notes=data["notes"],
    )

    # curve is included in the groups.

    for group in data["testGroups"]:
        vectors.curve = wp_curve_to_cc(group["curve"])

        if vectors.public_type and vectors.public_type != group["encoding"]:
            raise ValueError(
                f"Different encodings: {vectors.public_type} - {group['encoding']}"
            )
        if group["encoding"] == "ecpoint":
            vectors.public_type = "point"
        elif group["encoding"] == "asn":
            vectors.public_type = "x509"
        else:
            raise ValueError(f"Invalid encoding {group['encoding']}")

        for test in group["tests"]:
            new_test = vectors.tests.add(
                id=test["tcId"],
                type=test["result"],
                comment=test["comment"],
                flags=test["flags"],
                ss=bytes.fromhex(test["shared"]),
                d=bytes.fromhex(test["private"]),
            )
            if vectors.public_type == "point":
                new_test.peer_point = bytes.fromhex(test["public"])
            else:
                new_test.peer_x509 = bytes.fromhex(test["public"])

    dst = (
        VECTORS_DIR
        / "pb2"
        / f"ecdh_wycheproof_{vectors.curve}_{vectors.public_type}.pb2"
    )
    dst.write_bytes(vectors.SerializeToString())


def parse_wycheproof():
    """Parses all Wycheproof files selected for CC."""
    wp_dir = VECTORS_DIR / "wycheproof"
    for file in wp_dir.iterdir():
        if not file.suffix == ".json":
            continue
        _parse_wycheproof_file(file)


def generate_json() -> None:
    """Generates the JSON file indexing the vectors."""
    pb2_dir = VECTORS_DIR / "pb2"
    vectors: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))

    for file in pb2_dir.iterdir():
        cur = EcdhVectors()
        try:
            cur.ParseFromString(file.read_bytes())
        except Exception:
            print(f"[ERROR] Failed to read vectors from {file}")
            continue
        vectors[cur.curve][cur.public_type].append(str(file.name))

    out = VECTORS_DIR / "ecdh.json"
    with out.open("w") as fp:
        json.dump(vectors, fp, indent=2, sort_keys=True)


if __name__ == "__main__":
    imported_marker = VECTORS_DIR / "ecdh.imported"
    pb2_dir = VECTORS_DIR / "pb2"
    pb2_dir.mkdir(0o755, parents=False, exist_ok=True)

    try:
        parse_cavp()
        parse_wycheproof()
        generate_json()
    except Exception:
        imported_marker.unlink(missing_ok=True)
        print("[ERROR] Caught an exception, removing imported marker")
        raise
    else:
        imported_marker.touch()
