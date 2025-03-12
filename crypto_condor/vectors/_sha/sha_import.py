"""Module to import NIST SHA test vectors.

.. caution::
    This module is intended for developers of this tool, as it's only used for
    testing and packaging, has hard-coded filenames, and uses relative paths.
"""

import json
from collections import defaultdict
from pathlib import Path

from crypto_condor.vectors._sha.sha_pb2 import ShaVectors
from crypto_condor.vectors.SHA import Algorithm

VECTORS_DIR = Path("crypto_condor/vectors/_sha")


def parse_cavp(algo: Algorithm):
    """Parses SHA test vectors from NIST CAVP."""
    cavp_algo = (
        str(algo).replace("-512/", "512_").replace("SHA3-", "SHA3_").replace("-", "")
    )

    file = VECTORS_DIR / "cavp" / f"{cavp_algo}ShortMsg.rsp"
    blocks = file.read_text().split("\n\n")
    file = VECTORS_DIR / "cavp" / f"{cavp_algo}LongMsg.rsp"
    blocks += file.read_text().split("\n\n")

    vectors = ShaVectors(
        source="NIST CAVP",
        source_desc="Vectors from ShortMsg and LongMsg files.",
        source_url="https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing",
        compliance=True,
        algorithm=algo,
    )

    count = 0
    for block in blocks:
        block = block.strip()
        if not block or block.startswith(("#", "[")):
            continue

        count += 1

        test = vectors.tests.add(id=count, type="valid")

        is_null = False
        for line in block.split("\n"):
            key, value = line.split(" = ")
            match key:
                case "Len":
                    is_null = int(value) == 0
                case "Msg":
                    if is_null:
                        test.msg = b""
                        is_null = False
                    else:
                        test.msg = bytes.fromhex(value)
                case "MD":
                    test.md = bytes.fromhex(value)
                case _:
                    raise ValueError(f"Invalid key '{key}'")

    # Now parse Monte Carlo vectors.
    file = VECTORS_DIR / "cavp" / f"{cavp_algo}Monte.rsp"
    blocks = file.read_text().split("\n\n")

    count += 1
    vectors.mc_test.id = count
    vectors.mc_test.type = "valid"
    vectors.mc_test.flags.extend(["MonteCarlo"])

    count = 0
    for block in blocks:
        block = block.strip()
        if block.startswith(("#", "[")) or not block:
            continue
        for line in block.split("\n"):
            key, value = line.split(" = ")
            match key:
                case "Seed":
                    vectors.mc_test.seed = bytes.fromhex(value)
                case "COUNT":
                    count = int(value)
                case "MD":
                    vectors.mc_test.checkpoints[count] = bytes.fromhex(value)
                case _:
                    raise ValueError(f"Invalid key {key}")

    # Write the vectors to a file.
    file = VECTORS_DIR / "pb2" / f"cavp_{algo.file_safe}.pb2"
    file.write_bytes(vectors.SerializeToString())


def generate_json() -> None:
    """Generates the JSON file categorizing test vectors."""
    pb2_dir = VECTORS_DIR / "pb2"
    vectors: dict[str, list[str]] = defaultdict(list)

    for file in pb2_dir.iterdir():
        _vec = ShaVectors()
        _vec.ParseFromString(file.read_bytes())
        vectors[_vec.algorithm].append(file.name)

    out = VECTORS_DIR / "sha.json"
    with out.open("w") as fp:
        json.dump(vectors, fp, indent=2, sort_keys=True)


def check_fields() -> None:
    """Checks if all vectors contain the required fields."""
    pb2_dir = VECTORS_DIR / "pb2"
    for file in pb2_dir.iterdir():
        _vec = ShaVectors()
        _vec.ParseFromString(file.read_bytes())
        assert _vec.source, f"{file} missing source field"
        assert _vec.source_desc, f"{file} missing source_desc field"
        assert _vec.source_url, f"{file} missing source_url field"
        assert _vec.algorithm, f"{file} missing algorithm field"
        for test in _vec.tests:
            assert test.id, f"{file} test missing id field"
            assert test.type, f"{file} test missing type field"
            assert test.md, f"{file} test missing md field"


if __name__ == "__main__":
    pb2_dir = VECTORS_DIR / "pb2"
    pb2_dir.mkdir(exist_ok=True)
    imported_marker = VECTORS_DIR / "sha.imported"

    cavp_vectors = [algo for algo in Algorithm]

    try:
        for algo in cavp_vectors:
            parse_cavp(algo)
        generate_json()
        check_fields()
    except ValueError as error:
        print("[x] Failed to parse SHA vectors", str(error))
        imported_marker.unlink(missing_ok=True)
    except AssertionError as error:
        print("[x] Found invalid SHA test vectors:", str(error))
        imported_marker.unlink(missing_ok=True)
    else:
        imported_marker.touch()
