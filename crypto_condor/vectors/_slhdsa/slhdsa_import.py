"""Script to import SLH-DSA vectors.

.. caution::
    This module is intended for developers of this tool, as it's only used for
    testing and packaging, has hard-coded filenames, and uses relative paths.
"""

import json
from collections import defaultdict
from pathlib import Path

from crypto_condor.vectors._slhdsa.slhdsa_pb2 import SlhdsaVectors

VECTORS_DIR = Path("crypto_condor/vectors/_slhdsa")
PB2_DIR = VECTORS_DIR / "pb2"


def parse_acvp_keygen() -> None:
    """Parses test vectors for key generation from ACVP."""
    vectors_file = VECTORS_DIR / "acvp/keygen.json"
    with vectors_file.open("r") as fd:
        data = json.load(fd)

    for group in data["testGroups"]:
        paramset: str = group["parameterSet"]
        paramset = paramset.removeprefix("SLH-DSA-")
        vectors = SlhdsaVectors(
            source="ACVP",
            source_desc="ACVP test vectors for key pair generation",
            source_url="https://github.com/usnistgov/ACVP-Server/blob/85f8742965b2691862079172982683757d8d91db/gen-val/json-files/SLH-DSA-keyGen-FIPS205/internalProjection.json",
            compliance=True,
            operation="keygen",
            paramset=paramset,
        )
        for test in group["tests"]:
            vectors.tests.add(
                id=test["tcId"],
                type="valid",
                sk=bytes.fromhex(test["sk"]),
                pk=bytes.fromhex(test["pk"]),
                skseed=bytes.fromhex(test["skSeed"]),
                skprf=bytes.fromhex(test["skPrf"]),
                pkseed=bytes.fromhex(test["pkSeed"]),
            )

        out = PB2_DIR / f"slhdsa_acvp_keygen_{paramset}.pb2"
        out.write_bytes(vectors.SerializeToString())


def parse_acvp_siggen() -> None:
    """Parses test vectors from ACVP.

    Only parses the test vectors for the external signature interface.
    """
    vectors_file = VECTORS_DIR / "acvp/siggen.json"
    with vectors_file.open("r") as fd:
        data = json.load(fd)

    for group in data["testGroups"]:
        # Only use tests for the external API.
        if group["signatureInterface"] == "internal":
            continue
        # We currently don't support testing the hedged signing with test vectors.
        # TODO: remove this condition when adding hedged signing support.
        if not group["deterministic"]:
            continue
        paramset: str = group["parameterSet"]
        paramset = paramset.removeprefix("SLH-DSA-")
        vectors = SlhdsaVectors(
            source="ACVP",
            source_desc="ACVP test vectors for signature generation",
            source_url="https://github.com/usnistgov/ACVP-Server/blob/85f8742965b2691862079172982683757d8d91db/gen-val/json-files/SLH-DSA-sigGen-FIPS205/internalProjection.json",
            compliance=True,
            operation="siggen",
            paramset=paramset,
            prehash=group["preHash"] == "preHash",
        )
        for test in group["tests"]:
            vectors.tests.add(
                id=test["tcId"],
                type="valid",
                sk=bytes.fromhex(test["sk"]),
                pk=bytes.fromhex(test["pk"]),
                msg=bytes.fromhex(test["message"]),
                sig=bytes.fromhex(test["signature"]),
                ctx=bytes.fromhex(test["context"]),
                ph=test.get("hashAlg", ""),
            )

        filename = "slhdsa_acvp_siggen_" + paramset
        if vectors.prehash:
            filename += "_prehash"
        filename += "_det.pb2"
        out = PB2_DIR / filename
        out.write_bytes(vectors.SerializeToString())


def parse_acvp_sigver() -> None:
    """Parses test vectors from ACVP.

    Only parses the test vectors for the external verifying interface.
    """
    vectors_file = VECTORS_DIR / "acvp/sigver.json"
    with vectors_file.open("r") as fd:
        data = json.load(fd)

    for group in data["testGroups"]:
        # Only use tests for the external API.
        if group["signatureInterface"] == "internal":
            continue
        paramset: str = group["parameterSet"]
        paramset = paramset.removeprefix("SLH-DSA-")
        vectors = SlhdsaVectors(
            source="ACVP",
            source_desc="ACVP test vectors for signature verification",
            source_url="https://github.com/usnistgov/ACVP-Server/blob/85f8742965b2691862079172982683757d8d91db/gen-val/json-files/SLH-DSA-sigVer-FIPS205/internalProjection.json",
            compliance=True,
            operation="sigver",
            paramset=paramset,
            prehash=group["preHash"] == "preHash",
        )
        for test in group["tests"]:
            vectors.tests.add(
                id=test["tcId"],
                type="valid" if test["testPassed"] else "invalid",
                comment=test.get("reason", ""),
                pk=bytes.fromhex(test["pk"]),
                msg=bytes.fromhex(test["message"]),
                sig=bytes.fromhex(test["signature"]),
                ctx=bytes.fromhex(test["context"]),
                ph=test.get("hashAlg", ""),
            )

        filename = "slhdsa_acvp_sigver_" + paramset
        if vectors.prehash:
            filename += "_prehash"
        filename += ".pb2"
        out = PB2_DIR / filename
        out.write_bytes(vectors.SerializeToString())


def generate_json() -> None:
    """Generates the JSON file indexing the vectors."""
    vectors: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))

    for file in PB2_DIR.iterdir():
        cur = SlhdsaVectors()
        try:
            cur.ParseFromString(file.read_bytes())
        except Exception:
            print("[ERROR] Failed to read vectors from %s", file)
            continue

        vectors[cur.operation][cur.paramset].append(str(file.name))

    out = Path("crypto_condor/vectors/_slhdsa/slhdsa.json")
    with out.open("w") as fp:
        json.dump(vectors, fp, indent=2, sort_keys=True)


if __name__ == "__main__":
    # Ensure that the output directory exists.
    PB2_DIR.mkdir(0o755, parents=False, exist_ok=True)

    # Define the placeholder that Make uses to compile only when necessary.
    imported_marker = VECTORS_DIR / "slhdsa.imported"

    try:
        parse_acvp_keygen()
        parse_acvp_siggen()
        parse_acvp_sigver()
        generate_json()
    except Exception:
        imported_marker.unlink(missing_ok=True)
        raise
    else:
        imported_marker.touch()
