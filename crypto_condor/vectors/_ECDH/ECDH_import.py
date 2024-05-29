"""Script to parse ECDH vectors.

.. caution::
    This module is intended for developers of this tool, as it's only used for
    testing and packaging, has hard-coded filenames, and uses relative paths.
"""

import json
from pathlib import Path

from crypto_condor.vectors._ECDH.ECDH_pb2 import EcdhNistVectors, EcdhWycheproofVectors

VECTORS_DIR = Path("crypto_condor/vectors/_ECDH")


def nist_to_protobuf() -> None:
    """Parses NIST vectors and serializes them with protobuf."""
    # Only one source.
    file = VECTORS_DIR / "src/nist/KAS_ECC_CDH_PrimitiveTest.txt"
    data = file.read_text()
    blocks = [block.strip() for block in data.split("\n\n")]

    # Initialize a "null" vectors instance to distinguish when we already have a real
    # instance.
    vectors: EcdhNistVectors | None = None
    curve = ""

    for block in blocks:
        if not block or block.startswith("#"):
            continue
        # Curve sections start with e.g. [P-192]
        if block.startswith("["):
            # If we already have an instance, commit it.
            if vectors is not None:
                out = VECTORS_DIR / "dat" / f"nist_{curve}.dat"
                out.write_bytes(vectors.SerializeToString())
            # So we initialize a new instance of vectors.
            vectors = EcdhNistVectors()
            # Determine the curve name
            curve = block.lstrip("[").rstrip("]")
            vectors.curve = curve
            # Nothing more to do with this block.
            continue

        assert vectors is not None, "vectors is None, missed instantiation"

        # If we reached this point, we should only have blocks with actual test vectors
        # data.
        test = vectors.tests.add()
        lines = block.split("\n")
        for line in lines:
            key, value = line.split(" = ")
            match key:
                case "COUNT":
                    test.count = int(value)
                case "QCAVSx":
                    test.peer_x = bytes.fromhex(value)
                case "QCAVSy":
                    test.peer_y = bytes.fromhex(value)
                case "dIUT":
                    test.own_d = bytes.fromhex(value)
                case "QIUTx":
                    test.own_x = bytes.fromhex(value)
                case "QIUTy":
                    test.own_y = bytes.fromhex(value)
                case "ZIUT":
                    test.z = bytes.fromhex(value)
                case _:
                    raise ValueError(f"Unknown key {key}")

    # Commit last vectors.
    assert vectors is not None, "vectors is None, missed loop"
    out = VECTORS_DIR / "dat" / f"nist_{curve}.dat"
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


def wycheproof_to_protobuf(src: str) -> None:
    """Serialize Wycheproof vectors.

    Args:
        src: The name of the source file.
    """
    file = VECTORS_DIR / "src/wycheproof" / src
    with file.open("r") as fp:
        data = json.load(fp)

    vectors = EcdhWycheproofVectors()
    vectors.filename = src
    vectors.algorithm = data["algorithm"]
    vectors.generator_version = data["generatorVersion"]
    vectors.number_of_tests = int(data["numberOfTests"])
    vectors.header = " ".join(data["header"])
    vectors.notes.update(data["notes"])
    vectors.schema = data["schema"]

    for gp in data["testGroups"]:
        group = vectors.groups.add()
        curve = wp_curve_to_cc(gp["curve"])
        # Not sure we actually need this attribute so leave the original curve for now.
        group.curve = gp["curve"]
        group.encoding = gp["encoding"]
        group.type = gp["type"]
        test_type = "eckey" if gp["type"] == "EcdhTest" else "ecpoint"
        for t in gp["tests"]:
            test = group.tests.add()
            test.id = t["tcId"]
            test.comment = t["comment"]
            test.public = bytes.fromhex(t["public"])
            test.private = bytes.fromhex(t["private"])
            test.shared = bytes.fromhex(t["shared"])
            test.result = t["result"]
            test.flags.extend(t["flags"])

    dst = VECTORS_DIR / "dat" / f"wycheproof_{curve}_{test_type}.dat"
    dst.write_bytes(vectors.SerializeToString())


if __name__ == "__main__":
    dst = VECTORS_DIR / "dat"
    dst.mkdir(0o755, parents=False, exist_ok=True)

    nist_to_protobuf()

    wycheproof_files = [
        "ecdh_brainpoolP224r1_test.json",
        "ecdh_brainpoolP256r1_test.json",
        "ecdh_brainpoolP320r1_test.json",
        "ecdh_brainpoolP384r1_test.json",
        "ecdh_brainpoolP512r1_test.json",
        "ecdh_secp224r1_test.json",
        "ecdh_secp256r1_test.json",
        "ecdh_secp384r1_test.json",
        "ecdh_secp521r1_test.json",
        "ecdh_secp256k1_test.json",
        "ecdh_sect283k1_test.json",
        "ecdh_sect409k1_test.json",
        "ecdh_sect571k1_test.json",
        "ecdh_sect283r1_test.json",
        "ecdh_sect409r1_test.json",
        "ecdh_sect571r1_test.json",
    ]
    for file in wycheproof_files:
        wycheproof_to_protobuf(file)

    imported_marker = VECTORS_DIR / "ECDH.imported"
    imported_marker.touch()
