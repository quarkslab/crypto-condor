"""Script to import Ed25519 vectors.

.. caution::
    This module is intended for developers of this tool, as it's only used for
    testing and packaging, has hard-coded filenames, and uses relative paths.
"""

import json
from collections import defaultdict
from pathlib import Path

from crypto_condor.vectors._ed25519.ed25519_pb2 import Ed25519Vectors

VECTORS_DIR = Path("crypto_condor/vectors/_ed25519")
PB2_DIR = VECTORS_DIR / "pb2"


def parse_wycheproof_ed25519() -> None:
    """Parses Wycheproof test vectors for Ed25519."""
    path = VECTORS_DIR / "wycheproof/ed25519_test.json"

    with path.open("r") as fp:
        data = json.load(fp)

    wp_notes = data["notes"]
    notes: dict[str, str] = dict()
    for note, value in wp_notes.items():
        description = value["description"]
        if value.get("effect", None):
            description += " " + value["effect"]
        notes[note] = description

    vectors = Ed25519Vectors(
        source="Wycheproof",
        source_desc="Resilience test vectors for Ed25519 verification",
        source_url="https://github.com/C2SP/wycheproof/blob/main/testvectors_v1/ed25519_test.json",
        compliance=False,
        notes=notes,
        variant="Ed25519",
        sign=False,
        verify=True,
    )

    for group in data["testGroups"]:
        pk = bytes.fromhex(group["publicKey"]["pk"])
        for test in group["tests"]:
            vectors.tests.add(
                id=test["tcId"],
                type=test["result"],
                comment=test["comment"],
                flags=test["flags"],
                pk=pk,
                msg=bytes.fromhex(test["msg"]),
                sig=bytes.fromhex(test["sig"]),
            )

    dst = PB2_DIR / "ed25519_wycheproof.pb2"
    dst.write_bytes(vectors.SerializeToString())


def parse_rfc():
    """Parses test vectors from RFC 8032."""
    path = VECTORS_DIR / "rfc8032/ed25519_test.json"
    with path.open("r") as fp:
        data = json.load(fp)

    vectors = Ed25519Vectors(
        source="RFC8032",
        source_desc=data["description"],
        source_url=data["url"],
        compliance=True,
        notes=data["notes"],
        variant=data["variant"],
        sign=data["sign"],
        verify=data["verify"],
    )

    for test in data["tests"]:
        vectors.tests.add(
            id=test["id"],
            type=test["result"],
            comment=test["comment"],
            flags=test["flags"],
            sk=bytes.fromhex(test["sk"]),
            pk=bytes.fromhex(test["pk"]),
            msg=bytes.fromhex(test["msg"]),
            sig=bytes.fromhex(test["sig"]),
        )

    dst = PB2_DIR / "ed25519_rfc8032.pb2"
    dst.write_bytes(vectors.SerializeToString())


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
        cur = Ed25519Vectors()
        try:
            cur.ParseFromString(file.read_bytes())
        except Exception:
            print("[ERROR] Failed to read vectors from %s", file)
            continue

        vectors[cur.variant].append(str(file.name))

        # Otherwise, here is the equivalent for the two-level example: we do have to
        # check whether the first key is present, but we can still use defaultdict for
        # the second level.
        #
        # if cur.curve not in vectors:
        #     vectors[cur.curve] = defaultdict(list)
        # vectors[cur.curve][cur.public_type].append(str(file.name))

    out = Path("crypto_condor/vectors/_ed25519/ed25519.json")
    with out.open("w") as fp:
        json.dump(vectors, fp, indent=2, sort_keys=True)


if __name__ == "__main__":
    # Ensure that the output directory exists.
    PB2_DIR.mkdir(0o755, parents=False, exist_ok=True)

    # Define the placeholder that Make uses to compile only when necessary.
    imported_marker = VECTORS_DIR / "ed25519.imported"

    try:
        parse_wycheproof_ed25519()
        parse_rfc()
        generate_json()
    except Exception as error:
        print(f"[!] Error parsing Ed25519 test vectors: {error}")
        print("[!] Removed ed25519.imported marker")
        imported_marker.unlink(missing_ok=True)
        exit(1)
    else:
        imported_marker.touch()
