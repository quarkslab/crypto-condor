"""Module to import NIST CRYSTALS-Kyber test vectors.

.. caution::
    This module is intended for developers of this tool, as it's only used for
    testing and packaging, has hard-coded filenames, and uses relative paths.
"""

from pathlib import Path

from crypto_condor.vectors._kyber.kyber_pb2 import KyberNistVectors

VECTORS_DIR = Path("crypto_condor/vectors/_kyber")


def rsp_to_protobuf(name: str):
    """Imports Kyber KAT test vectors.

    The file is parsed and serialized with
    :class:`crypto_condor.vectors.nist.kyber.kyber_pb2.KyberNistVectors`.

    The files will be named Kyber{512,768,1024}[-90s].dat

    Args:
        name: The name of the Kyber parameter set, e.g. Kyber512.
    """
    # WARN: hard-coded path.
    file = VECTORS_DIR / "rsp" / f"{name}.rsp"

    # Vectors are separated by a newline so by splitting on two newlines we get all
    # blocks separately.
    blocks = file.read_text().split("\n\n")

    vectors = KyberNistVectors()

    for block in blocks:
        block = block.strip()
        if not block or block.startswith("#"):
            continue
        vector = vectors.tests.add()
        lines = block.split("\n")
        for line in lines:
            key, value = line.split(" = ")
            match key:
                case "count":
                    setattr(vector, key, int(value))
                case "seed" | "pk" | "sk" | "ct" | "ss":
                    setattr(vector, key, bytes.fromhex(value))
                case _:
                    raise ValueError(f"Unknown key {key}")

    file = VECTORS_DIR / "dat" / f"{name}.dat"
    file.write_bytes(vectors.SerializeToString())


if __name__ == "__main__":
    dat_dir = VECTORS_DIR / "dat"
    dat_dir.mkdir(exist_ok=True)

    parameter_sets = [
        "Kyber512",
        "Kyber512-90s",
        "Kyber768",
        "Kyber768-90s",
        "Kyber1024",
        "Kyber1024-90s",
    ]

    for param in parameter_sets:
        rsp_to_protobuf(param)

    imported_marker = VECTORS_DIR / "kyber.imported"
    imported_marker.touch()
