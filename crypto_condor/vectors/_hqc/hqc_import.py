"""Script to import HQC vectors.

.. caution::
    This module is intended for developers of this tool, as it's only used for
    testing and packaging, has hard-coded filenames, and uses relative paths.
"""

import json
from collections import defaultdict
from pathlib import Path

from crypto_condor.vectors._hqc.hqc_pb2 import HqcVectors

VECTORS_DIR = Path("crypto_condor/vectors/_hqc")
PB2_DIR = VECTORS_DIR / "pb2"


def _parse_ref_file(filename: str, paramset: str) -> None:
    file = VECTORS_DIR / "ref" / filename
    blocks = file.read_text().split("\n\n")

    vectors = HqcVectors(
        source="Reference implementation",
        source_desc="Test vectors generated using the NIST KAT script",
        compliance=True,
        paramset=paramset,
    )

    for block in blocks:
        block = block.strip()
        if not block or block.startswith("#"):
            continue
        test = vectors.tests.add(type="valid")
        for line in block.split("\n"):
            k, v = line.split(" = ")
            match k:
                case "count":
                    test.id = int(v) + 1
                case "seed":
                    continue
                case "pk" | "sk" | "ct" | "ss":
                    setattr(test, k, bytes.fromhex(v))
                case _:
                    raise ValueError(f"Invalid key {k}")

    out = PB2_DIR / f"hqc_ref_{paramset[4:]}.pb2"
    out.write_bytes(vectors.SerializeToString())


def parse_ref() -> None:
    """Parses the test vectors generated with the reference implementation."""
    files = [
        ("PQCkemKAT_2305.rsp", "HQC-128"),
        ("PQCkemKAT_4586.rsp", "HQC-192"),
        ("PQCkemKAT_7317.rsp", "HQC-256"),
    ]
    for filename, paramset in files:
        _parse_ref_file(filename, paramset)


def generate_json() -> None:
    """Generates the JSON file indexing the vectors."""
    # This is an example of a single level dictionary. Using defaultdict(list) means
    # that we can easily append values to a new key without having to check the
    # existence of the key or the list.
    vectors: dict[str, list[str]] = defaultdict(list)

    for file in PB2_DIR.iterdir():
        cur = HqcVectors()
        try:
            cur.ParseFromString(file.read_bytes())
        except Exception:
            print("[ERROR] Failed to read vectors from %s", file)
            continue
        vectors[cur.paramset].append(str(file.name))

    out = Path("crypto_condor/vectors/_hqc/hqc.json")
    with out.open("w") as fp:
        json.dump(vectors, fp, indent=2, sort_keys=True)


if __name__ == "__main__":
    # Ensure that the output directory exists.
    PB2_DIR.mkdir(0o755, parents=False, exist_ok=True)

    # Define the placeholder that Make uses to compile only when necessary.
    imported_marker = VECTORS_DIR / "hqc.imported"

    try:
        parse_ref()
        generate_json()
    except Exception:
        imported_marker.unlink(missing_ok=True)
    else:
        imported_marker.touch()
