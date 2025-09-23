"""Script to import PLACEHOLDER vectors.

.. caution::
    This module is intended for developers of this tool, as it's only used for
    testing and packaging, has hard-coded filenames, and uses relative paths.
"""

import json
from collections import defaultdict
from pathlib import Path

from crypto_condor.vectors._LCPLACEHOLDER.LCPLACEHOLDER_pb2 import CapPLACEHOLDERVectors

VECTORS_DIR = Path("crypto_condor/vectors/_LCPLACEHOLDER")
PB2_DIR = VECTORS_DIR / "pb2"


def generate_json() -> None:
    """Generates the JSON file indexing the vectors."""
    # This is an example of a single level dictionary. Using defaultdict(list) means
    # that we can easily append values to a new key without having to check the
    # existence of the key or the list.
    vectors: dict[str, list[str]] = defaultdict(list)

    # This is an example of a two-level dict based on ECDH, whose vectors are separated
    # by elliptic curve, and then by type of public key.
    #
    # vectors: dict[str, dict[str, list[str]]] = dict()

    for file in PB2_DIR.iterdir():
        cur = CapPLACEHOLDERVectors()
        try:
            cur.ParseFromString(file.read_bytes())
        except Exception:
            print("[ERROR] Failed to read vectors from %s", file)
            continue

        # FIXME: parameter is the attribute that categorises the vectors. If you changed
        # the name in the proto descriptor, change it here too.
        vectors[cur.parameter].append(str(file.name))

        # Otherwise, here is the equivalent for the two-level example: we do have to
        # check whether the first key is present, but we can still use defaultdict for
        # the second level.
        #
        # if cur.curve not in vectors:
        #     vectors[cur.curve] = defaultdict(list)
        # vectors[cur.curve][cur.public_type].append(str(file.name))

    out = Path("crypto_condor/vectors/_LCPLACEHOLDER/LCPLACEHOLDER.json")
    with out.open("w") as fp:
        json.dump(vectors, fp, indent=2, sort_keys=True)


if __name__ == "__main__":
    # Ensure that the output directory exists.
    PB2_DIR.mkdir(0o755, parents=False, exist_ok=True)

    # Define the placeholder that Make uses to compile only when necessary.
    imported_marker = VECTORS_DIR / "LCPLACEHOLDER.imported"

    try:
        # FIXME: import vectors here and generate JSON at the end
        generate_json()
    except Exception as error:
        print(f"[!] Error parsing LCPLACEHOLDER test vectors: {error}")
        print("[!] Removed LCPLACEHOLDER.imported marker")
        imported_marker.unlink(missing_ok=True)
        exit(1)
    else:
        imported_marker.touch()
