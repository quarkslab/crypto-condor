"""Module to import NIST ECDSA test vectors.

.. caution::
    This module is intended for developers of this tool, as it's only used for
    testing and packaging, has hard-coded filenames, and uses relative paths.
    For use within the Makefile, ``cd`` to the corresponding directory first.
"""

import csv
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from crypto_condor.primitives.ECDSA import Curve, Hash
from crypto_condor.vectors._ecdsa.ecdsa_pb2 import (
    EcdsaSigGenVectors,
    EcdsaSigVerVectors,
)

# WARN: hard-coded path.
VECTORS_DIR = Path("crypto_condor/vectors/_ecdsa")

CURVES = [
    "P-224",
    "P-256",
    "P-384",
    "P-521",
    "B-283",
    "B-409",
    "B-571",
    "secp256k1",
    "brainpoolP256r1",
    "brainpoolP384r1",
    "brainpoolP521r1",
]
HASHES = [
    "SHA-224",
    "SHA-256",
    "SHA-384",
    "SHA-512",
    "SHA-512/224",
    "SHA-512/256",
    "SHA3-224",
    "SHA3-256",
    "SHA3-384",
    "SHA3-512",
]


def parse_cavp_sigver(filename: str) -> None:
    """Parses NIST CAVP signature verification vectors."""
    vectors_file = VECTORS_DIR / "cavp" / filename
    blocks = vectors_file.read_text().split("\n\n")

    vectors: EcdsaSigVerVectors | None = None
    count = 0
    skip = False

    for block in blocks:
        block = block.strip()
        if not block or block.startswith("#"):
            continue
        if skip and not block.startswith("["):
            continue

        # New section of test vectors for a (curve, hash) tuple.
        if block.startswith("["):
            skip = False
            # If there is an active instance, commit it.
            if vectors is not None:
                # Truncated hashes have a forward slash in the name which must be
                # removed.
                h = vectors.hash.replace("/", "_")
                out = VECTORS_DIR / "pb2" / f"cavp-sigver-{vectors.curve}-{h}.pb2"
                out.write_bytes(vectors.SerializeToString())
            # Check if curve is one of the ones we want.
            curve, algo = block.lstrip("[").rstrip("]").split(",")
            if curve not in CURVES:
                skip = True
                continue
            if len(algo) > 7:
                # It's a truncated hash, insert forward slash in the name.
                algo = algo[:7] + "/" + algo[7:]

            # Create a new instance.
            vectors = EcdsaSigVerVectors(
                source="NIST CAVP",
                source_desc=(
                    "Vectors from NIST's Cryptographic Algorithm Validation Program"
                ),
                source_url="https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Digital-Signatures#ecdsa2vs",
                compliance=True,
                curve=curve,
                hash=algo,
            )
            # Start the ID counter.
            count = 1
            # We're done setting up the vectors, continue to parse the tests.
            continue

        # From here, all blocks are supposed to be tests. We should have a valid
        # instance of vectors.
        assert vectors is not None

        test = vectors.tests.add()
        test.id = count
        count += 1

        # Create variables to fill, then combine them and add them to the test.
        qx = ""
        qy = ""
        r = 0
        s = 0

        for line in block.split("\n"):
            key, value = line.split(" = ")
            match key:
                case "Msg":
                    test.msg = bytes.fromhex(value)
                case "Qx":
                    qx = value
                case "Qy":
                    qy = value
                case "R":
                    r = int(value, 16)
                case "S":
                    s = int(value, 16)
                case "Result":
                    if value.startswith("P"):
                        test.type = "valid"
                    else:
                        test.type = "invalid"
                        # The value is of the form:
                        # F (3 - S changed)
                        # We focus on the comment at the end of the line.
                        test.comment = value[7:].rstrip(")")
                case _:
                    raise ValueError("Unknown key '%s'", key)

        # Save the public key as an encoded, uncompressed point.
        test.pubkey = bytes.fromhex(f"04{qx}{qy}")
        # Save the signature as an ASN-encoded signature.
        test.sig = encode_dss_signature(r, s)

    # Commit the last instance.
    assert vectors is not None
    # Truncated hashes have a forward slash in the name which must be removed.
    h = vectors.hash.replace("/", "_")
    out = VECTORS_DIR / "pb2" / f"cavp-sigver-{vectors.curve}-{h}.pb2"
    out.write_bytes(vectors.SerializeToString())


def parse_cavp_siggen(filename: str) -> None:
    """Parses NIST CAVP signature generation vectors."""
    vectors_file = VECTORS_DIR / "cavp" / filename
    blocks = vectors_file.read_text().split("\n\n")

    vectors: EcdsaSigGenVectors | None = None
    count = 0
    skip = False

    for block in blocks:
        block = block.strip()
        if not block or block.startswith("#"):
            continue
        if skip and not block.startswith("["):
            continue

        # New section of test vectors for a (curve, hash) tuple.
        if block.startswith("["):
            skip = False
            # If there is an active instance, commit it.
            if vectors is not None:
                # Truncated hashes have a forward slash in the name which must be
                # removed.
                h = vectors.hash.replace("/", "_")
                out = VECTORS_DIR / "pb2" / f"cavp-siggen-{vectors.curve}-{h}.pb2"
                out.write_bytes(vectors.SerializeToString())
            # Check if curve is one of the ones we want.
            curve, algo = block.lstrip("[").rstrip("]").split(",")
            if curve not in CURVES:
                skip = True
                continue
            if len(algo) > 7:
                # It's a truncated hash, insert forward slash in the name.
                algo = algo[:7] + "/" + algo[7:]

            # Create a new instance.
            vectors = EcdsaSigGenVectors(
                source="NIST CAVP",
                source_desc=(
                    "Vectors from NIST's Cryptographic Algorithm Validation Program"
                ),
                source_url="https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Digital-Signatures#ecdsa2vs",
                compliance=True,
                curve=curve,
                hash=algo,
            )
            # Start the ID counter.
            count = 1
            # We're done setting up the vectors, continue to parse the tests.
            continue

        # From here, all blocks are supposed to be tests. We should have a valid
        # instance of vectors.
        assert vectors is not None

        test = vectors.tests.add()
        test.id = count
        count += 1
        test.type = "valid"

        for line in block.split("\n"):
            key, value = line.split(" = ")
            match key:
                case "Msg":
                    test.msg = bytes.fromhex(value)
                case "d":
                    if len(value) % 2 == 1:
                        value = "0" + value
                    test.d = bytes.fromhex(value)
                case "Qx" | "Qy" | "R" | "S" | "k":
                    # Valid but unused variables.
                    continue
                case _:
                    raise ValueError("Unknown key '%s'", key)

    # Commit the last instance.
    assert vectors is not None
    # Truncated hashes have a forward slash in the name which must be removed.
    h = vectors.hash.replace("/", "_")
    out = VECTORS_DIR / "pb2" / f"cavp-siggen-{vectors.curve}-{h}.pb2"
    out.write_bytes(vectors.SerializeToString())


def parse_wycheproof_sigver(path: Path) -> None:
    """Parses Wycheproof signature verification vectors."""
    with path.open("r") as file:
        data = json.load(file)

    # Use the parameters from the same group, as all groups in a file use the same set.
    curve = Curve.from_name(data["testGroups"][0]["key"]["curve"])
    algo = Hash.from_name(data["testGroups"][0]["sha"])

    vectors = EcdsaSigVerVectors(
        source="Wycheproof",
        source_desc="Verification vectors of ASN encoded ECDSA signatures",
        source_url="https://github.com/C2SP/wycheproof/tree/master/testvectors",
        compliance=False,
        notes=data["notes"],
        curve=curve,
        hash=algo,
    )

    for group in data["testGroups"]:
        key = bytes.fromhex(group["key"]["uncompressed"])
        for ref in group["tests"]:
            vectors.tests.add(
                id=ref["tcId"],
                type=ref["result"],
                comment=ref["comment"],
                flags=ref["flags"],
                msg=bytes.fromhex(ref["msg"]),
                sig=bytes.fromhex(ref["sig"]),
                pubkey=key,
            )

    out = VECTORS_DIR / "pb2" / f"wycheproof-sigver-{vectors.curve}-{vectors.hash}.pb2"
    out.write_bytes(vectors.SerializeToString())


def generate_json() -> None:
    """Generates the JSON file categorizing test vectors."""
    pb2_dir = VECTORS_DIR / "pb2"
    vectors: dict[str, dict[str, dict[str, list[str]]]] = {
        "siggen": dict(),
        "sigver": dict(),
    }

    for file in pb2_dir.iterdir():
        if "siggen" in file.name:
            _vec = EcdsaSigGenVectors()
            curves = vectors["siggen"]
        else:
            _vec = EcdsaSigVerVectors()
            curves = vectors["sigver"]
        _vec.ParseFromString(file.read_bytes())

        if _vec.curve not in curves:
            curves[_vec.curve] = dict()

        hashes = curves[_vec.curve]
        if _vec.hash not in hashes:
            hashes[_vec.hash] = list()

        hashes[_vec.hash].append(file.name)

    out = VECTORS_DIR / "ecdsa.json"
    with out.open("w") as fp:
        json.dump(vectors, fp, indent=2)


def generate_csv() -> None:
    """Generates the CSV tables for the documentation.

    They describe which test vectors sources are available depending on the curve and
    hash function.
    """
    pb2_dir = VECTORS_DIR / "pb2"
    # That's one heck of a type annotation. It boils down to:
    # {"siggen":
    #   "P-192":  {
    #     "SHA-256": {
    #       "compliance": True,
    #       "resilience": False,
    #     },
    #   },
    # }
    vectors: dict[str, dict[str, dict[str, dict[str, bool]]]] = {
        "siggen": dict(),
        "sigver": dict(),
    }

    for file in pb2_dir.iterdir():
        if file.name == ".gitkeep":
            continue

        if "siggen" in file.name:
            _vec = EcdsaSigGenVectors()
            curves = vectors["siggen"]
        else:
            _vec = EcdsaSigVerVectors()
            curves = vectors["sigver"]
        _vec.ParseFromString(file.read_bytes())

        if _vec.curve not in curves:
            curves[_vec.curve] = dict()

        hashes = curves[_vec.curve]
        if _vec.hash not in hashes:
            hashes[_vec.hash] = {"compliance": False, "resilience": False}

        if _vec.compliance:
            hashes[_vec.hash]["compliance"] = True
        else:
            hashes[_vec.hash]["resilience"] = True

    out_gen = VECTORS_DIR / "ecdsa_siggen.csv"
    out_ver = VECTORS_DIR / "ecdsa_sigver.csv"

    with out_gen.open("w", newline="") as fp:
        curves = vectors["siggen"]
        writer = csv.writer(fp, delimiter=",")
        # Exclude SHA-3 since there are no vectors.
        writer.writerow([""] + HASHES[:6])

        for curve in CURVES:
            if curve not in curves:
                continue
            line = [curve]
            hashes = curves[curve]
            for h in HASHES[:6]:
                if h not in hashes:
                    line.append("x")
                    continue
                types = list()
                if hashes[h]["compliance"]:
                    types.append(":green:`C`")
                if hashes[h]["resilience"]:
                    types.append(":blue:`R`")
                line.append(" + ".join(types))
            writer.writerow(line)

    with out_ver.open("w", newline="") as fp:
        curves = vectors["sigver"]
        writer = csv.writer(fp, delimiter=",")
        writer.writerow([""] + HASHES)

        for curve in CURVES:
            if curve not in curves:
                continue
            line = [curve]
            hashes = curves[curve]
            for h in HASHES:
                if h not in hashes:
                    line.append("x")
                    continue
                types = list()
                if hashes[h]["compliance"]:
                    types.append(":green:`C`")
                if hashes[h]["resilience"]:
                    types.append(":blue:`R`")
                line.append(" + ".join(types))
            writer.writerow(line)


if __name__ == "__main__":
    pb2_dir = VECTORS_DIR / "pb2"
    pb2_dir.mkdir(exist_ok=True)

    sig_ver_files = ["SigVer.rsp", "SigVer_TruncatedSHAs.rsp"]
    for filename in sig_ver_files:
        parse_cavp_sigver(filename)

    sig_gen_files = ["SigGen.txt", "SigGen_TruncatedSHAs.txt"]
    for filename in sig_gen_files:
        parse_cavp_siggen(filename)

    for path in Path(VECTORS_DIR / "wycheproof").iterdir():
        if path.is_dir():
            continue
        parse_wycheproof_sigver(path)

    generate_json()
    generate_csv()

    imported_marker = VECTORS_DIR / "ecdsa.imported"
    imported_marker.touch()
