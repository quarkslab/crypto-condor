"""Module to import ML-KEM test vectors.

.. caution::
    This module is intended for developers of this tool, as it's only used for
    testing and packaging, has hard-coded filenames, and uses relative paths.
"""

from pathlib import Path

from crypto_condor.vectors._mlkem.mlkem_pb2 import MlkemVectors

VECTORS_DIR = Path("crypto_condor/vectors/_mlkem")


def parse_nistkat(in_filename: str):
    """Parses vectors generated using NIST KAT generator."""
    # WARN: hard-coded path
    file = VECTORS_DIR / "nistkat" / in_filename

    blocks = file.read_text().split("\n\n")

    vectors = MlkemVectors()
    vectors.source = "NIST KAT"
    vectors.source_desc = (
        "Vectors generated with the reference implementation"
        " and the generator provided by NIST"
    )
    vectors.source_url = "https://github.com/pq-crystals/kyber/tree/main/ref/nistkat"
    vectors.compliance = True
    match in_filename:
        case "PQCkemKAT_1632.rsp":
            vectors.paramset = "ML-KEM-512"
        case "PQCkemKAT_2400.rsp":
            vectors.paramset = "ML-KEM-768"
        case "PQCkemKAT_3168.rsp":
            vectors.paramset = "ML-KEM-1024"
        case _:
            raise ValueError(f"Unsupported file {in_filename}")

    for block in blocks:
        block = block.strip()
        if not block or block.startswith("#"):
            continue

        test = vectors.tests.add()
        test.type = "valid"

        lines = block.split("\n")
        for line in lines:
            key, value = line.split(" = ")
            match key:
                case "count":
                    test.id = int(value) + 1
                case "seed":
                    # Currently not included in the definition of the test.
                    pass
                case "pk" | "sk" | "ct" | "ss":
                    setattr(test, key, bytes.fromhex(value))
                case _:
                    raise ValueError(f"Unknown key {key}")

    file = VECTORS_DIR / "pb2" / f"{file.stem}.pb2"
    file.write_bytes(vectors.SerializeToString())


if __name__ == "__main__":
    pb2_dir = VECTORS_DIR / "pb2"
    pb2_dir.mkdir(exist_ok=True)

    nistkat_files = ["PQCkemKAT_1632.rsp", "PQCkemKAT_2400.rsp", "PQCkemKAT_3168.rsp"]
    for filename in nistkat_files:
        parse_nistkat(filename)

    imported_marker = VECTORS_DIR / "mlkem.imported"
    imported_marker.touch()
