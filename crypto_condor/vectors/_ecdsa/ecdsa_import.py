"""Module to import NIST ECDSA test vectors.

.. caution::
    This module is intended for developers of this tool, as it's only used for
    testing and packaging, has hard-coded filenames, and uses relative paths.
    For use within the Makefile, ``cd`` to the corresponding directory first.
"""

from pathlib import Path

from crypto_condor.vectors._ecdsa.ecdsa_pb2 import (
    EcdsaNistSigGenVectors,
    EcdsaNistSigVerVectors,
)

VECTORS_DIR = Path("crypto_condor/vectors/_ecdsa")


def import_sigver() -> EcdsaNistSigVerVectors:
    """Imports SigVer test vectors."""
    # WARN: hard-coded path.
    vectors_dir = Path("crypto_condor/vectors/_ecdsa")
    in_file = vectors_dir / "rsp" / "SigVer.rsp"

    with open(in_file, "r") as file:
        data = file.readlines()

    vector = None
    vectors = None

    count = 1
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

        # '[' indicates the start of a new group (curve+hash).
        if line.startswith("["):
            # If a group of vectors already exists, it's complete and we commit it.
            if vectors is not None:
                file = (
                    vectors_dir
                    / "dat"
                    / f"ecdsa_sigver_{vectors.curve}_{vectors.hash_algo}.dat"
                )
                file.write_bytes(vectors.SerializeToString())
            curve, hash_algo = line.split(",")
            curve = curve.lstrip("[")
            hash_algo = hash_algo.rstrip("]")
            vectors = EcdsaNistSigVerVectors()
            vectors.name = f"{curve} with {hash_algo}"
            vectors.curve = curve
            vectors.hash_algo = hash_algo
            continue

        # We continue'd comments, empty lines, and headers so the current line
        # must be data.
        key, value = line.split(" = ")
        match key:
            case "Msg":
                vector = vectors.tests.add()
                vector.message = value
                vector.id = count
                count += 1
                vector.line_number = line_number
            case "Qx" | "Qy" | "R" | "S":
                setattr(vector, key.lower(), value)
            case "Result":
                if value[0] == "P":
                    vector.result = "valid"
                elif value[0] == "F":
                    vector.result = "invalid"
                    # Take the part after the dash, remove the closing parentheses.
                    reason = value.split(" - ")[-1].rstrip(")")
                    vector.fail_reason = reason

    file = vectors_dir / "dat" / f"ecdsa_sigver_{vectors.curve}_{vectors.hash_algo}.dat"
    file.write_bytes(vectors.SerializeToString())


def import_siggen() -> EcdsaNistSigGenVectors:
    """Imports SigGen test vectors."""
    # WARN: hard-coded path.
    vectors_dir = Path("crypto_condor/vectors/_ecdsa")
    in_file = vectors_dir / "rsp" / "SigGen.txt"

    with open(in_file, "r") as file:
        data = file.readlines()

    vector = None
    vectors = None

    count = 1
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

        # '[' indicates the start of a new group (curve+hash).
        if line.startswith("["):
            # If a group of vectors already exists, it's complete and we commit it.
            if vectors is not None:
                file = (
                    vectors_dir
                    / "dat"
                    / f"ecdsa_siggen_{vectors.curve}_{vectors.hash_algo}.dat"
                )
                file.write_bytes(vectors.SerializeToString())
            curve, hash_algo = line.split(",")
            curve = curve.lstrip("[")
            hash_algo = hash_algo.rstrip("]")
            vectors = EcdsaNistSigGenVectors()
            vectors.name = f"{curve} with {hash_algo}"
            vectors.curve = curve
            vectors.hash_algo = hash_algo
            continue

        # We continue'd comments, empty lines, and headers so the current line
        # must be data.
        key, value = line.split(" = ")
        match key:
            case "Msg":
                vector = vectors.tests.add()
                vector.message = value
                vector.id = count
                count += 1
                vector.line_number = line_number
            case "d" | "Qx" | "Qy" | "k" | "R" | "S":
                setattr(vector, key.lower(), value)

    file = vectors_dir / "dat" / f"ecdsa_siggen_{vectors.curve}_{vectors.hash_algo}.dat"
    file.write_bytes(vectors.SerializeToString())


def main():
    """Imports all ECDSA test vectors."""
    dat_dir = VECTORS_DIR / "dat"
    dat_dir.mkdir(exist_ok=True)

    import_sigver()
    import_siggen()

    vectors_dir = Path("crypto_condor/vectors/_ecdsa")
    imported_marker = vectors_dir / "ecdsa.imported"
    imported_marker.touch()


if __name__ == "__main__":
    main()
