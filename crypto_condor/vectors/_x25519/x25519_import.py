"""Script to import x25519 vectors.

.. caution::
    This module is intended for developers of this tool, as it's only used for
    testing and packaging, has hard-coded filenames, and uses relative paths.
"""

import json
from pathlib import Path

from crypto_condor.vectors._x25519.x25519_pb2 import X25519Vectors

VECTORS_DIR = Path("crypto_condor/vectors/_x25519")
PB2_DIR = VECTORS_DIR / "pb2"


def parse_rfc():
    """Parses test vectors from RFC 7748."""
    path = VECTORS_DIR / "rfc7748/x25519_test.json"
    with path.open("r") as fp:
        data = json.load(fp)

    vectors = X25519Vectors(
        source="RFC7748",
        source_desc=data["description"],
        source_url=data["url"],
        compliance=True,
        notes=data["notes"],
    )

    for test in data["tests"]:
        vectors.tests.add(
            id=test["id"],
            type=test["result"],
            comment=test["comment"],
            flags=test["flags"],
            sk=bytes.fromhex(test["sk"]),
            pk=bytes.fromhex(test["pk"]),
            shared=bytes.fromhex(test["shared"])
        )

    dst = PB2_DIR / "x25519_rfc7748.pb2"
    dst.write_bytes(vectors.SerializeToString())


def parse_wycheproof_x25519() -> None:
    """Parses Wycheproof test vectors for Ed25519."""
    path = VECTORS_DIR / "wycheproof/x25519_test.json"

    with path.open("r") as fp:
        data = json.load(fp)

    wp_notes = data["notes"]
    notes: dict[str, str] = dict()
    for note, value in wp_notes.items():
        description = value["description"]
        if value.get("effect", None):
            description += " " + value["effect"]
        notes[note] = description

    vectors = X25519Vectors(
        source="Wycheproof",
        source_desc="Resilience test vectors for X25519 key exchange",
        source_url="https://github.com/C2SP/wycheproof/blob/5595df3a728dcea01e6d2135b8c509b7331be84a/testvectors_v1/x25519_test.json",
        compliance=False,
        notes=notes,
    )

    for group in data["testGroups"]:
        for test in group["tests"]:
            vectors.tests.add(
                id=test["tcId"],
                type=test["result"],
                comment=test["comment"],
                flags=test["flags"],
                sk=bytes.fromhex(test["private"]),
                pk=bytes.fromhex(test["public"]),
                shared=bytes.fromhex(test["shared"]),
            )

    dst = PB2_DIR / "x25519_wycheproof.pb2"
    dst.write_bytes(vectors.SerializeToString())


def generate_json() -> None:
    """Generates the JSON file indexing the vectors."""
    # This is an example of a single level dictionary. Using defaultdict(list) means
    # that we can easily append values to a new key without having to check the
    # existence of the key or the list.
    # vectors: dict[str, list[str]] = defaultdict(list)
    vectors: list[str] = list()

    # This is an example of a two-level dict based on ECDH, whose vectors are separated
    # by elliptic curve, and then by type of public key.
    #
    # vectors: dict[str, dict[str, list[str]]] = dict()

    for file in PB2_DIR.iterdir():
        cur = X25519Vectors()
        try:
            cur.ParseFromString(file.read_bytes())
        except Exception:
            print("[ERROR] Failed to read vectors from %s", file)
            continue

        # NOTE: no parameter for X25519.
        vectors.append(str(file.name))

        # Otherwise, here is the equivalent for the two-level example: we do have to
        # check whether the first key is present, but we can still use defaultdict for
        # the second level.
        #
        # if cur.curve not in vectors:
        #     vectors[cur.curve] = defaultdict(list)
        # vectors[cur.curve][cur.public_type].append(str(file.name))

    out = Path("crypto_condor/vectors/_x25519/x25519.json")
    with out.open("w") as fp:
        json.dump(vectors, fp, indent=2, sort_keys=True)


if __name__ == "__main__":
    # Ensure that the output directory exists.
    PB2_DIR.mkdir(0o755, parents=False, exist_ok=True)

    # Define the placeholder that Make uses to compile only when necessary.
    imported_marker = VECTORS_DIR / "x25519.imported"

    try:
        parse_rfc()
        parse_wycheproof_x25519()
        generate_json()
    except Exception as error:
        print(f"[!] Error parsing x25519 test vectors: {error}")
        print("[!] Removed x25519.imported marker")
        imported_marker.unlink(missing_ok=True)
        exit(1)
    else:
        imported_marker.touch()
