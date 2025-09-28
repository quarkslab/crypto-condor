"""Script to import PLACEHOLDER vectors.

.. caution::
    This module is intended for developers of this tool, as it's only used for
    testing and packaging, has hard-coded filenames, and uses relative paths.
"""

import json
from collections import defaultdict
from pathlib import Path

from crypto_condor.vectors._chacha20.chacha20_pb2 import Chacha20Vectors

VECTORS_DIR = Path("crypto_condor/vectors/_chacha20")
PB2_DIR = VECTORS_DIR / "pb2"


def _parse_wp_json(file: Path, vectors: Chacha20Vectors, out_name: str) -> None:
    """Parses a Wycheproof-like JSON file."""
    with file.open("r") as fd:
        data = json.load(fd)

    vectors.source_desc = " ".join(data["header"])
    vectors.notes.update(data["notes"])
    vectors.notes.update({"InvalidNonceSize": "FIXME", "ModifiedTag": "FIXME"})

    for group in data["testGroups"]:
        for test in group["tests"]:
            flags = list(test["flags"])
            if test["comment"] == "invalid nonce size":
                flags.append("InvalidNonceSize")
            elif "tag" in test["comment"].lower():
                flags.append("ModifiedTag")
            vectors.tests.add(
                id=test["tcId"],
                type=test["result"],
                comment=test["comment"],
                flags=flags,
                key=bytes.fromhex(test["key"]),
                nonce=bytes.fromhex(test["iv"]),
                pt=bytes.fromhex(test["msg"]),
                ct=bytes.fromhex(test["ct"]),
                aad=bytes.fromhex(test.get("aad", "")),
                tag=bytes.fromhex(test.get("tag", "")),
                counter=test.get("init_counter", 0),
            )
    out = PB2_DIR / out_name
    out.write_bytes(vectors.SerializeToString())


def parse_cc() -> None:
    """Parses crypto-condor test vectors."""
    file = VECTORS_DIR / "cc/chacha20_test.json"
    vectors = Chacha20Vectors(
        source="crypto-condor",
        compliance=True,
        mode="CHACHA20",
    )
    _parse_wp_json(file, vectors, "chacha20_cc.pb2")


def parse_wycheproof() -> None:
    """Parses Wycheproof test vectors for ChaCha20-Poly1305."""
    file = VECTORS_DIR / "wycheproof/chacha20_poly1305_test.json"
    vectors = Chacha20Vectors(
        source="Wycheproof",
        source_url="https://github.com/C2SP/wycheproof/tree/master/testvectors",
        compliance=False,
        mode="CHACHA20-POLY1305",
    )
    _parse_wp_json(file, vectors, "chacha20_wycheproof_poly1305.pb2")


def generate_json() -> None:
    """Generates the JSON file indexing the vectors."""
    pb2_dir = VECTORS_DIR / "pb2"

    # This is an example of a single level dictionary. Using defaultdict(list) means
    # that we can easily append values to a new key without having to check the
    # existence of the key or the list.
    vectors: dict[str, list[str]] = defaultdict(list)

    # This is an example of a two-level dict based on ECDH, whose vectors are separated
    # by elliptic curve, and then by type of public key.
    #
    # vectors: dict[str, dict[str, list[str]]] = dict()

    for file in pb2_dir.iterdir():
        cur = Chacha20Vectors()
        try:
            cur.ParseFromString(file.read_bytes())
        except Exception:
            print("[ERROR] Failed to read vectors from %s", file)
            continue

        vectors[cur.mode].append(str(file.name))

        # Otherwise, here is the equivalent for the two-level example: we do have to
        # check whether the first key is present, but we can still use defaultdict for
        # the second level.
        #
        # if cur.curve not in vectors:
        #     vectors[cur.curve] = defaultdict(list)
        # vectors[cur.curve][cur.public_type].append(str(file.name))

    out = Path("crypto_condor/vectors/_chacha20/chacha20.json")
    with out.open("w") as fp:
        json.dump(vectors, fp, indent=2)


if __name__ == "__main__":
    # Ensure that the output directory exists.
    PB2_DIR.mkdir(0o755, parents=False, exist_ok=True)

    # Define the placeholder that Make uses to compile only when necessary.
    imported_marker = VECTORS_DIR / "chacha20.imported"

    try:
        parse_cc()
        parse_wycheproof()
        generate_json()
    except Exception:
        imported_marker.unlink(missing_ok=True)
        raise
    else:
        imported_marker.touch()
