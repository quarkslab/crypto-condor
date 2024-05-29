"""Module to import NIST Falcon test vectors.

.. caution::
    This module is intended for developers of this tool, as it's only used for
    testing and packaging, has hard-coded filenames, and uses relative paths.
"""

from pathlib import Path

from crypto_condor.vectors._falcon.falcon_pb2 import (
    FalconNistKatTest,
    FalconNistKatVectors,
)

VECTORS_DIR = Path("crypto_condor/vectors/_falcon")


def import_kat_vectors(name: str):
    """Imports KAT test vectors.

    The file is parsed and serialized with
    :class:`crypto_condor.vectors._falcon.falcon_pb2.FalconNistKatVectors`.

    The files should be named falcon{512,1024}.rsp.

    Args:
        name: The name of the Falcon parameter set, e.g. falcon512.
    """
    # WARN: hard-coded path.
    falcon_dir = Path("crypto_condor/vectors/_falcon")
    file = falcon_dir / "rsp" / f"{name}.rsp"
    data = file.read_text().split("\n")

    vectors = FalconNistKatVectors()
    vector: FalconNistKatTest

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

    file = falcon_dir / "dat" / f"{name}.dat"
    file.write_bytes(vectors.SerializeToString())


def main():
    """Imports Falcon KAT test vectors."""
    dat_dir = VECTORS_DIR / "dat"
    dat_dir.mkdir(exist_ok=True)

    parameter_sets = [
        "falcon512",
        "falcon1024",
    ]

    for param in parameter_sets:
        import_kat_vectors(param)

    vectors_dir = Path("crypto_condor/vectors/_falcon")
    imported_marker = vectors_dir / "falcon.imported"
    imported_marker.touch()


if __name__ == "__main__":
    main()
