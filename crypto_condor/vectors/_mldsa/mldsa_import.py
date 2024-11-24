"""Module to import ML-DSA test vectors.

.. caution::
    This module is intended for developers of this tool, as it's only used for
    testing and packaging, has hard-coded filenames, and uses relative paths.
"""

from pathlib import Path

from crypto_condor.vectors._mldsa.mldsa_pb2 import MldsaVectors

VECTORS_DIR = Path("crypto_condor/vectors/_mldsa")

SIG_SIZE = {"ML-DSA-44": 2420, "ML-DSA-65": 3309, "ML-DSA-87": 4627}


def parse_nistkat(in_filename: str):
    """Parses vectors generated using NIST KAT generator."""
    # WARN: hard-coded path
    file = VECTORS_DIR / "nistkat" / in_filename

    blocks = file.read_text().split("\n\n")

    vectors = MldsaVectors()
    vectors.source = "NIST KAT"
    vectors.source_desc = (
        "Vectors generated with the reference implementation"
        " and the generator provided by NIST"
    )
    vectors.source_url = (
        "https://github.com/pq-crystals/dilithium/tree/master/ref/nistkat"
    )
    vectors.compliance = True
    match in_filename:
        case "PQCsignKAT_Dilithium2.rsp":
            vectors.paramset = "ML-DSA-44"
        case "PQCsignKAT_Dilithium3.rsp":
            vectors.paramset = "ML-DSA-65"
        case "PQCsignKAT_Dilithium5.rsp":
            vectors.paramset = "ML-DSA-87"
        case _:
            raise ValueError(f"Unsupported file {in_filename}")
    sig_size = SIG_SIZE[vectors.paramset]

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
                case "msg" | "pk" | "sk":
                    setattr(test, key, bytes.fromhex(value))
                case "sm":
                    _sm = bytes.fromhex(value)
                    sig = _sm[:sig_size]
                    test.sig = sig
                case "seed":
                    # We don't store the seed.
                    pass
                case "mlen" | "smlen":
                    # We don't store the size of msg or sm, just compute it from
                    # the actual value when needed.
                    pass
                case _:
                    raise ValueError(f"Unknown key {key}")

    file = VECTORS_DIR / "pb2" / f"nistkat-{vectors.paramset}.pb2"
    file.write_bytes(vectors.SerializeToString())


if __name__ == "__main__":
    pb2_dir = VECTORS_DIR / "pb2"
    pb2_dir.mkdir(exist_ok=True)

    nistkat_files = [
        "PQCsignKAT_Dilithium2.rsp",
        "PQCsignKAT_Dilithium3.rsp",
        "PQCsignKAT_Dilithium5.rsp",
    ]
    for filename in nistkat_files:
        parse_nistkat(filename)

    imported_marker = VECTORS_DIR / "mldsa.imported"
    imported_marker.touch()
