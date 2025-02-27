"""Module to import NIST HMAC test vectors."""

import json
from collections import defaultdict
from pathlib import Path

from crypto_condor.vectors._hmac.hmac_pb2 import HmacVectors

VECTORS_DIR = Path("crypto_condor/vectors/_hmac")


def parse_cavp() -> None:
    """Parses NIST CAVP test vectors."""
    # The vectors are separated by the length of the hash function in bytes, from which
    # we infer the actual hash function used (there are no vectors for SHA-512/224,
    # SHA-512/256, or SHA-3 functions so there is no ambiguity).
    hashes = {20: "SHA-1", 28: "SHA-224", 32: "SHA-256", 48: "SHA-384", 64: "SHA-512"}

    with open(f"{VECTORS_DIR}/cavp/HMAC.rsp", "r") as file:
        blocks = file.read().split("\n\n")

    vectors: HmacVectors | None = None

    for block in blocks:
        block = block.strip()
        if not block or block.startswith("#"):
            continue

        if block.startswith("["):
            # We are starting a new section so commit any previous vectors.
            if vectors is not None:
                out = VECTORS_DIR / "pb2" / f"hmac_cavp_{vectors.hash}.pb2"
                out.write_bytes(vectors.SerializeToString())
            # [L=20]
            # 0..3.5
            hlen = int(block[3:5])
            hash_name = hashes[hlen]
            vectors = HmacVectors(
                source="NIST CAVP",
                source_desc="Test vectors from HMAC.rsp",
                source_url="https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/message-authentication",
                compliance=True,
                hash=hash_name,
            )
            # Nothing more to do with this block
            continue

        # Sanity check.
        assert vectors is not None, "vectors is None"

        # If we've reached this point, the block must be data.
        test = vectors.tests.add()
        # We know that all CAVP HMAC vectors are valid.
        test.type = "valid"

        for line in block.split("\n"):
            key, value = line.split(" = ")
            match key:
                case "Count":
                    # We use count as the ID. We add 1 to start the count at 1.
                    test.id = int(value) + 1
                case "Klen" | "Tlen":
                    # We don't use these parameters, they are inferred from the actual
                    # values.
                    continue
                case "Key" | "Msg" | "Mac":
                    setattr(test, key.lower(), bytes.fromhex(value))
                case _:
                    raise ValueError(f"Invalid key {key}")

    assert vectors is not None, "vectors is None, missed instantiation"
    # Commit last batch.
    out = VECTORS_DIR / "pb2" / f"hmac_cavp_{vectors.hash}.pb2"
    out.write_bytes(vectors.SerializeToString())


def parse_wycheproof(in_file: str, hash_name: str) -> None:
    """Parses Wycheproof test vectors."""
    file = VECTORS_DIR / "wycheproof" / in_file
    with file.open("r") as fp:
        data = json.load(fp)

    vectors = HmacVectors(
        source="Wycheproof",
        source_desc=" ".join(data["header"]),
        source_url=f"https://github.com/C2SP/wycheproof/tree/master/testvectors/{in_file}",
        compliance=False,
        notes=data["notes"],
        hash=hash_name,
    )

    for data_group in data["testGroups"]:
        for test in data_group["tests"]:
            vectors.tests.add(
                id=int(test["tcId"]),
                type=test["result"],
                comment=test["comment"],
                flags=test["flags"],
                key=bytes.fromhex(test["key"]),
                msg=bytes.fromhex(test["msg"]),
                mac=bytes.fromhex(test["tag"]),
            )

    out = VECTORS_DIR / "pb2" / f"hmac_wycheproof_{vectors.hash}.pb2"
    out.write_bytes(vectors.SerializeToString())


def generate_json() -> None:
    """Generates the JSON file categorizing test vectors."""
    pb2_dir = VECTORS_DIR / "pb2"
    vectors: dict[str, list[str]] = defaultdict(list)

    for file in pb2_dir.iterdir():
        _vec = HmacVectors()
        _vec.ParseFromString(file.read_bytes())
        vectors[_vec.hash].append(file.name)

    out = VECTORS_DIR / "hmac.json"
    with out.open("w") as fp:
        json.dump(vectors, fp, indent=2, sort_keys=True)


if __name__ == "__main__":
    pb2_dir = VECTORS_DIR / "pb2"
    pb2_dir.mkdir(0o755, exist_ok=True)

    wp_files = (
        ("hmac_sha1_test.json", "SHA-1"),
        ("hmac_sha224_test.json", "SHA-224"),
        ("hmac_sha256_test.json", "SHA-256"),
        ("hmac_sha384_test.json", "SHA-384"),
        ("hmac_sha512_test.json", "SHA-512"),
        ("hmac_sha3_224_test.json", "SHA3-224"),
        ("hmac_sha3_256_test.json", "SHA3-256"),
        ("hmac_sha3_384_test.json", "SHA3-384"),
        ("hmac_sha3_512_test.json", "SHA3-512"),
    )

    try:
        parse_cavp()
        for in_file, hash_name in wp_files:
            parse_wycheproof(in_file, hash_name)
    except Exception as error:
        print(str(error))
    else:
        generate_json()
        Path(VECTORS_DIR / "hmac.imported").touch()
