"""Module to import SHAKE test vectors.

.. caution::
    This module is intended for developers of this tool, as it's only used for
    testing and packaging, has hard-coded filenames, and uses relative paths.
"""

import json
from collections import defaultdict
from pathlib import Path

from crypto_condor.vectors._shake.shake_pb2 import ShakeVectors

VECTORS_DIR = Path("crypto_condor/vectors/_shake")


def parse_cavp(algorithm: str, orientation: str):
    """Parses SHAKE test vectors from NIST CAVP."""
    assert algorithm in {"SHAKE128", "SHAKE256"}
    assert orientation in {"bit", "byte"}
    file = VECTORS_DIR / "cavp" / orientation / f"{algorithm}ShortMsg.rsp"
    blocks = file.read_text().split("\n\n")
    file = VECTORS_DIR / "cavp" / orientation / f"{algorithm}LongMsg.rsp"
    blocks += file.read_text().split("\n\n")
    file = VECTORS_DIR / "cavp" / orientation / f"{algorithm}VariableOut.rsp"
    blocks += file.read_text().split("\n\n")

    vectors = ShakeVectors(
        source="NIST CAVP",
        source_desc="Vectors from the ShortMsg and LongMsg files.",
        source_url="https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing#sha3vsha3vss",
        compliance=True,
        algorithm=algorithm,
        orientation=orientation,
    )

    count = 0
    for block in blocks:
        block = block.strip()
        if not block or block.startswith(("#", "[")):
            continue

        count += 1

        test = vectors.tests.add()
        test.id = count
        test.type = "valid"

        is_null = False
        lines = block.split("\n")
        for line in lines:
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
                case "Output":
                    test.out = bytes.fromhex(value)
                case "COUNT":
                    # Since we are combining the files we do not use the included count.
                    continue
                case "Outputlen":
                    # We recompute the output length at runtime from the output.
                    continue
                case _:
                    raise ValueError("Unknown key '%s'" % key)

    # Now parse Monte-Carlo vectors.
    file = VECTORS_DIR / "cavp" / orientation / f"{algorithm}Monte.rsp"
    blocks = file.read_text().split("\n\n")

    count += 1
    vectors.mc_test.id = count
    vectors.mc_test.type = "valid"
    vectors.mc_test.flags.extend(["MonteCarlo"])

    count = 0
    for block in blocks:
        block = block.strip()
        if block.startswith("#") or not block:
            continue
        if block.startswith("["):
            line = block.lstrip("[").rstrip().rstrip("]")
            key, value = line.split(" = ")
            if "Minimum" in key:
                vectors.mc_test.min_len = int(value)
            elif "Maximum" in key:
                vectors.mc_test.max_len = int(value)
            continue

        for line in block.split("\n"):
            key, value = line.split(" = ")
            match key:
                case "Msg":
                    vectors.mc_test.seed = bytes.fromhex(value)
                case "COUNT":
                    count = int(value)
                case "Output":
                    vectors.mc_test.checkpoints[count] = bytes.fromhex(value)
                case "Outputlen":
                    continue
                case _:
                    raise ValueError(f"Unknown key {key}")

    # Finally, write the vectors to a file.
    file = VECTORS_DIR / "pb2" / f"cavp-{algorithm}-{orientation}.pb2"
    file.write_bytes(vectors.SerializeToString())


def generate_json() -> None:
    """Generates the JSON file categorizing test vectors."""
    pb2_dir = VECTORS_DIR / "pb2"
    vectors: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))

    for file in pb2_dir.iterdir():
        _vec = ShakeVectors()
        _vec.ParseFromString(file.read_bytes())
        vectors[_vec.algorithm][_vec.orientation].append(file.name)

    out = VECTORS_DIR / "shake.json"
    with out.open("w") as fp:
        json.dump(vectors, fp, indent=2)


def main():
    """Imports SHA test vectors."""
    pb2_dir = VECTORS_DIR / "pb2"
    pb2_dir.mkdir(exist_ok=True)

    params = [
        (algo, orient)
        for algo in {"SHAKE128", "SHAKE256"}
        for orient in {"bit", "byte"}
    ]

    for algo, orient in params:
        parse_cavp(algo, orient)

    generate_json()

    imported_marker = VECTORS_DIR / "shake.imported"
    imported_marker.touch()


if __name__ == "__main__":
    main()
