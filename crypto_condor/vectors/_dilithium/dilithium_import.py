"""Module to import NIST CRYSTALS-Dilithium test vectors.

.. caution::
    This module is intended for developers of this tool, as it's only used for
    testing and packaging, has hard-coded filenames, and uses relative paths.
"""

from pathlib import Path

from crypto_condor.vectors._dilithium.dilithium_pb2 import DilithiumNistVectors

VECTORS_DIR = Path("crypto_condor/vectors/_dilithium")


def import_kat_vectors(name: str):
    """Imports Dilithium KAT test vectors.

    The file is parsed and serialized with
    :class:`crypto_condor.vectors._dilithium.dilithium_pb2.DilithiumNistVectors`.

    The files will be named Dilithium{2,3,5}.dat

    Args:
        name: The name of the Dilithium parameter set, e.g. Dilithium2.
    """
    # WARN: hard-coded path.
    file = VECTORS_DIR / "rsp" / f"PQCsignKAT_{name}.rsp"
    # Vectors are separated by a newline so by splitting on two newlines we get all
    # blocks separately.
    blocks = file.read_text().split("\n\n")

    vectors = DilithiumNistVectors()

    for block in blocks:
        block = block.strip()
        if not block or block.startswith("#"):
            continue
        vector = vectors.tests.add()
        lines = block.split("\n")
        for line in lines:
            key, value = line.split(" = ")
            match key:
                case "count" | "mlen" | "smlen":
                    setattr(vector, key, int(value))
                case "seed" | "msg" | "pk" | "sk" | "sm":
                    setattr(vector, key, bytes.fromhex(value))
                case _:
                    raise ValueError(f"Unknown key {key}")

    file = VECTORS_DIR / "dat" / f"{name}.dat"
    file.write_bytes(vectors.SerializeToString())


if __name__ == "__main__":
    dat_dir = VECTORS_DIR / "dat"
    dat_dir.mkdir(exist_ok=True)

    parameter_sets = [
        "Dilithium2",
        "Dilithium3",
        "Dilithium5",
    ]

    for param in parameter_sets:
        import_kat_vectors(param)

    imported_marker = VECTORS_DIR / "dilithium.imported"
    imported_marker.touch()
