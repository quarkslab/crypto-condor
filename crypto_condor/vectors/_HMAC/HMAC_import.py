"""Module to import NIST HMAC test vectors."""

import json
from pathlib import Path

from crypto_condor.vectors._HMAC.HMAC_pb2 import (
    HmacNistTest,
    HmacNistVectors,
    HmacWycheproofVectors,
)

VECTORS_DIR = Path("crypto_condor/vectors/_HMAC/")
Path(VECTORS_DIR / "dat").mkdir(0o755, parents=False, exist_ok=True)


def rsp_to_protobuf() -> None:
    """Imports NIST test vectors from HMAC.rsp."""
    # The vectors are separated by the length of the hash function in bytes, from which
    # we infer the actual hash function used (there are no vectors for SHA-512/224,
    # SHA-512/256, or SHA-3 functions so there is no ambiguity).
    hashes = {20: "SHA-1", 28: "SHA-224", 32: "SHA-256", 48: "SHA-384", 64: "SHA-512"}

    with open(f"{VECTORS_DIR}/rsp/HMAC.rsp", "r") as file:
        lines = file.readlines()

    test: HmacNistTest
    vectors: HmacNistVectors | None = None

    for line_number, line in enumerate(lines, start=1):
        line = line.rstrip()
        if line.startswith("#") or not line:
            continue

        if line.startswith("["):
            # We are at the start of a new section so commit previous vectors and
            # create a new instance.
            if vectors is not None:
                Path(VECTORS_DIR / f"dat/{vectors.filename}").write_bytes(
                    vectors.SerializeToString()
                )
            # [L=20]
            # 0..3.5
            hlen = int(line[3:5])
            hash_name = hashes[hlen]
            vectors = HmacNistVectors()
            vectors.filename = f"hmac_nist_{hash_name}.dat"
            vectors.hashname = hash_name
            # Nothing more to do with this line.
            continue

        assert vectors is not None, "vectors is None, missed instantiation"

        key, value = line.split(" = ")
        match key:
            case "Count":
                # This is the first line of a test so create new instance.
                test = vectors.tests.add()
                test.count = int(value)
                test.line_number = line_number
            case "Klen" | "Tlen":
                setattr(test, key.lower(), int(value))
            case "Key" | "Msg" | "Mac":
                setattr(test, key.lower(), bytes.fromhex(value))
            case _:
                raise ValueError(f"Unknown key {key}")

    assert vectors is not None, "vectors is None, missed instantiation"
    # Commit last batch.
    Path(VECTORS_DIR / f"dat/{vectors.filename}").write_bytes(
        vectors.SerializeToString()
    )


def wycheproof_to_protobuf(in_file: str, out_file: str) -> None:
    """Import Wycheproof vectors to protobuf.

    Mainly to save some space and avoid converting hex to bytes elsewhere.
    """
    file = VECTORS_DIR / "wycheproof" / in_file
    with file.open("r") as fp:
        data = json.load(fp)

    vectors = HmacWycheproofVectors()
    vectors.filename = in_file
    vectors.algorithm = data["algorithm"]
    vectors.version = data["generatorVersion"]
    vectors.header.extend(data["header"])
    vectors.number_of_tests = data["numberOfTests"]
    vectors.notes.update(data["notes"])

    for data_group in data["testGroups"]:
        group = vectors.groups.add()
        group.key_size = data_group["keySize"]
        group.tag_size = data_group["tagSize"]
        for data_test in data_group["tests"]:
            test = group.tests.add()
            test.count = int(data_test["tcId"])
            test.comment = data_test["comment"]
            test.key = bytes.fromhex(data_test["key"])
            test.msg = bytes.fromhex(data_test["msg"])
            test.mac = bytes.fromhex(data_test["tag"])
            test.result = data_test["result"]
            test.flags.extend(data_test["flags"])

    with Path(VECTORS_DIR / "dat" / out_file).open("wb") as out:
        out.write(vectors.SerializeToString())


if __name__ == "__main__":
    rsp_to_protobuf()

    files = (
        ("hmac_sha1_test.json", "hmac_wp_SHA-1.dat"),
        ("hmac_sha224_test.json", "hmac_wp_SHA-224.dat"),
        ("hmac_sha256_test.json", "hmac_wp_SHA-256.dat"),
        ("hmac_sha384_test.json", "hmac_wp_SHA-384.dat"),
        ("hmac_sha512_test.json", "hmac_wp_SHA-512.dat"),
        ("hmac_sha3_224_test.json", "hmac_wp_SHA3-224.dat"),
        ("hmac_sha3_256_test.json", "hmac_wp_SHA3-256.dat"),
        ("hmac_sha3_384_test.json", "hmac_wp_SHA3-384.dat"),
        ("hmac_sha3_512_test.json", "hmac_wp_SHA3-512.dat"),
    )

    for in_file, out_file in files:
        wycheproof_to_protobuf(in_file, out_file)

    # Mark as imported.
    Path(VECTORS_DIR / "HMAC.imported").touch()
