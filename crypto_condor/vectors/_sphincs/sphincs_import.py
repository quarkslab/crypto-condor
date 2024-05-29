"""Module to import NIST sphincs test vectors.

.. caution::
    This module is intended for developers of this tool, as it's only used for
    testing and packaging, has hard-coded filenames, and uses relative paths.
"""

from pathlib import Path

from crypto_condor.vectors._sphincs.sphincs_pb2 import (
    SphincsNistKatTest,
    SphincsNistKatVectors,
)

VECTORS_DIR = Path("crypto_condor/vectors/_sphincs")


def import_kat_vectors(name: str):
    """Imports SPHINCS+ KAT test vectors.

    The file is parsed and serialized with
    :class:`crypto_condor.vectors._sphincs.sphincs_pb2.SphincsNistKatVectors`.

    Args:
        name: The name of the sphincs parameter set.
    """
    # WARN: hard-coded path.
    sphincs_dir = Path("crypto_condor/vectors/_sphincs")
    file = sphincs_dir / "rsp" / f"{name}.rsp"
    data = file.read_text().split("\n")

    vectors = SphincsNistKatVectors()
    vector: SphincsNistKatTest

    line_number = 0

    while True:
        try:
            line = data.pop(0)
            line_number += 1
        except IndexError:
            break

        # Remove leading whitespace.
        line = line.rstrip()

        # Ignore comments and empty lines.
        if line.startswith("#") or not line:
            continue

        # All other lines should be data.
        key, value = line.split(" = ")
        match key:
            case "count":
                vector = vectors.tests.add()
                vector.count = int(value)
                vector.line_number = line_number
            case "seed" | "msg" | "pk" | "sk" | "sm":
                setattr(vector, key.lower(), value)
            case "mlen" | "smlen":
                setattr(vector, key.lower(), int(value))
            case _:
                raise ValueError("Unknown key %s" % key)

    file = sphincs_dir / "dat" / f"{name}.dat"
    file.write_bytes(vectors.SerializeToString())


def main():
    """Imports Sphincs KAT test vectors."""
    dat_dir = VECTORS_DIR / "dat"
    dat_dir.mkdir(exist_ok=True)

    rsp_dir = Path("crypto_condor/vectors/_sphincs/rsp")
    for file in rsp_dir.iterdir():
        import_kat_vectors(file.stem)

    vectors_dir = Path("crypto_condor/vectors/_sphincs")
    imported_marker = vectors_dir / "sphincs.imported"
    imported_marker.touch()


if __name__ == "__main__":
    main()
