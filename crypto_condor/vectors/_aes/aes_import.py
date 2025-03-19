"""Module to import AES test vectors.

.. caution::
    This module is intended for developers of this tool, as it's only used for
    testing and packaging, has hard-coded filenames, and uses relative paths.
    For use within the Makefile, ``cd`` to the corresponding directory first.
"""

import json
from collections import defaultdict
from pathlib import Path

from crypto_condor.vectors._aes.aes_pb2 import AesVectors

VECTORS_DIR = Path("crypto_condor/vectors/_aes")

KEY_LENGTHS = {128, 192, 256}


def generate_cavp_files():
    """Returns a dictionary of NIST CAVP test vectors."""
    modes = ["ECB", "CBC", "CFB128", "CFB8"]
    types = ["GFSbox", "KeySbox", "MMT", "VarKey", "VarTxt"]
    klens = [128, 192, 256]

    files = {
        (mode, klen): [f"{mode}{t}{klen}.rsp" for t in types]
        for mode in modes
        for klen in klens
    }

    files.update({("CTR", klen): [f"CTR{klen}.rsp"] for klen in klens})
    files.update({("GCM", klen): [f"gcmEncryptExtIV{klen}.rsp"] for klen in klens})

    return files


def parse_cavp(mode: str, keylen: int, files: list[str]):
    """Parses NIST CAVP test vectors."""
    enc_vectors = AesVectors(
        source="NIST CAVP",
        source_desc="Test vectors from NIST's Cryptographic Algorithm Validation Program",  # noqa: E501
        source_url="https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers#AES",
        compliance=True,
        mode=mode,
        keylen=keylen,
        encrypt=True,
    )
    dec_vectors = AesVectors(
        source="NIST CAVP",
        source_desc="Test vectors from NIST's Cryptographic Algorithm Validation Program",  # noqa: E501
        source_url="https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers#AES",
        compliance=True,
        mode=mode,
        keylen=keylen,
        decrypt=True,
    )

    tid = 0
    for filename in files:
        file = VECTORS_DIR / "cavp" / filename
        blocks = file.read_text().split("\n\n")

        encrypt = True
        for block in blocks:
            if block.startswith("#") or not block:
                continue

            if block.startswith("[DECRYPT]"):
                encrypt = False

            # Ignore all other headers.
            if block.startswith("["):
                continue

            if encrypt:
                test = enc_vectors.tests.add()
            else:
                test = dec_vectors.tests.add()

            tid += 1
            test.id = tid
            test.type = "valid"

            for line in block.split("\n"):
                sp = line.split(" = ")
                if len(sp) == 1:
                    if sp[0] == "FAIL":
                        test.type = "invalid"
                        continue
                    else:
                        raise ValueError(f"Only one value in split: {sp}")

                key, value = sp

                match key:
                    case "COUNT" | "Count":
                        pass
                    case "KEY" | "Key" | "IV" | "PT" | "CT" | "AAD" | "Tag":
                        setattr(test, key.lower(), bytes.fromhex(value))
                    case "PLAINTEXT":
                        test.pt = bytes.fromhex(value)
                    case "CIPHERTEXT":
                        test.ct = bytes.fromhex(value)
                    case _:
                        raise ValueError(f"Unexpected {key = }")

    out_enc = VECTORS_DIR / "pb2" / f"aes_cavp_{mode}_{keylen}_enc.pb2"
    out_enc.write_bytes(enc_vectors.SerializeToString())
    if mode != "GCM":
        out_dec = VECTORS_DIR / "pb2" / f"aes_cavp_{mode}_{keylen}_dec.pb2"
        out_dec.write_bytes(dec_vectors.SerializeToString())


def parse_cavp_gcm_decrypt(keylen: int, filename: str) -> None:
    """Parses CAVP GCM decryption test vectors.

    The format is slightly different, with invalid tests marked with FAIL instead of
    having a plaintext.
    """
    vectors = AesVectors(
        source="NIST CAVP",
        source_desc="Decryption test vectors for AES-GCM",
        source_url="https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/CAVP-TESTING-BLOCK-CIPHER-MODES#GCMVS",
        compliance=True,
        mode="GCM",
        keylen=keylen,
        decrypt=True,
    )

    file = VECTORS_DIR / "cavp" / filename

    tid = 0
    blocks = file.read_text().split("\n\n")
    for block in blocks:
        if not block.strip() or block.startswith(("#", "[")):
            continue
        # We can set the test type to valid by default, then change it if needed.
        test = vectors.tests.add(type="valid")
        for line in block.split("\n"):
            if line.strip() == "FAIL":
                test.type = "invalid"
                continue
            k, v = line.split(" = ")
            match k:
                case "Count":
                    tid += 1
                    test.id = tid
                case "Key" | "IV" | "Tag" | "CT" | "PT" | "AAD":
                    setattr(test, k.lower(), bytes.fromhex(v))
                case _:
                    raise ValueError(f"Invalid key {k}")

    out = VECTORS_DIR / "pb2" / f"aes_cavp_gcm_{keylen}_dec.pb2"
    out.write_bytes(vectors.SerializeToString())


def parse_cavp_ccm(keylen: int, files: list[str]) -> None:
    """Parses NIST CAVP test vectors for AES-CCM."""
    vectors = AesVectors(
        source="NIST CAVP",
        source_desc="Combines the VADT, VPT, VNT, and VTT files for a single key length",  # noqa: E501
        source_url="https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/CAVP-TESTING-BLOCK-CIPHER-MODES#CCM",
        compliance=True,
        mode="CCM",
        keylen=keylen,
        encrypt=True,
    )

    tid = 0

    for filename in files:
        file = VECTORS_DIR / "cavp" / filename
        lines = file.read_text().split("\n")

        alen, plen = -1, -1
        key, nonce, aad, pt, ct = b"", b"", b"", b"", b""

        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("["):
                line = line.lstrip("[").rstrip("]")
                k, val = line.split(" = ")
                if k == "Alen":
                    alen = int(val)
                if k == "Plen":
                    plen = int(val)
                continue

            k, val = line.split(" = ")
            match k:
                case "Plen" | "Nlen" | "Tlen" | "Alen" | "Count":
                    continue
                case "Key":
                    key = bytes.fromhex(val)
                case "Nonce":
                    nonce = bytes.fromhex(val)
                case "Adata":
                    aad = bytes.fromhex(val) if alen != 0 else b""
                case "Payload":
                    pt = bytes.fromhex(val) if plen != 0 else b""
                case "CT":
                    ct_and_tag = bytes.fromhex(val)
                    ct = ct_and_tag[: len(pt)]
                    tag = ct_and_tag[len(pt) :]
                    tid += 1
                    vectors.tests.add(
                        id=tid,
                        type="valid",
                        key=key,
                        pt=pt,
                        ct=ct,
                        iv=nonce,
                        aad=aad,
                        tag=tag,
                    )

    out = VECTORS_DIR / "pb2" / f"aes_cavp_ccm_{vectors.keylen}.pb2"
    out.write_bytes(vectors.SerializeToString())


def parse_cavp_ccm_dvpt(keylen: int, filename: str) -> None:
    """Parses NIST CAVP DVPT files for CCM.

    Due to their exotic format, it is simpler to have a separate function.
    """
    vectors = AesVectors(
        source="NIST CAVP",
        source_desc=f"From the {filename} file",
        source_url="https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/CAVP-TESTING-BLOCK-CIPHER-MODES#CCM",
        compliance=True,
        mode="CCM",
        keylen=keylen,
        encrypt=False,
        decrypt=True,
    )

    tid = 0
    file = VECTORS_DIR / "cavp" / filename
    lines = file.read_text().split("\n")

    alen, plen = -1, -1
    key, nonce, aad, pt, ct = b"", b"", b"", b"", b""

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        if line.startswith("["):
            line = line.lstrip("[").rstrip("]")
            params = line.split(", ")
            for kv in params:
                k, v = kv.split(" = ")
                # Alen and Plen can be 0, meaning that the value is b"".
                if k == "Alen":
                    alen = int(v)
                if k == "Plen":
                    plen = int(v)
            continue

        k, v = line.split(" = ")
        match k:
            case "Key":
                key = bytes.fromhex(v)
            case "Count":
                continue
            case "Nonce":
                nonce = bytes.fromhex(v)
            case "Adata":
                aad = bytes.fromhex(v) if alen != 0 else b""
            case "CT":
                b_ct = bytes.fromhex(v)
                ct = b_ct[:plen]
                tag = b_ct[plen:]
            case "Result":
                if v.startswith("Pass"):
                    continue
                # If the test is invalid, there is no payload afterwards so we can
                # directly add the test.
                tid += 1
                vectors.tests.add(
                    id=tid,
                    type="invalid",
                    # Comment is in the form 'Fail (2 - CT changed)'
                    comment=v.split(" - ")[1].rstrip(")"),
                    key=key,
                    ct=ct,
                    iv=nonce,
                    aad=aad,
                    tag=tag,
                )
            case "Payload":
                pt = bytes.fromhex(v) if plen != 0 else b""
                # If the result is Pass, the last field is Payload.
                tid += 1
                vectors.tests.add(
                    id=tid,
                    type="valid",
                    key=key,
                    pt=pt,
                    ct=ct,
                    iv=nonce,
                    aad=aad,
                    tag=tag,
                )
            case _:
                raise ValueError(f"Invalid key {k}")

    out = VECTORS_DIR / "pb2" / f"aes_cavp_ccm_{str(keylen)}_dvpt.pb2"
    out.write_bytes(vectors.SerializeToString())


def parse_wycheproof(filename: str):
    """Parses Wycheproof test vectors."""
    pb2_dir = VECTORS_DIR / "pb2"

    vectors_file = VECTORS_DIR / "wycheproof" / filename
    with vectors_file.open("r") as file:
        data = json.load(file)

    mode = data["algorithm"].lstrip("AES-")

    v128 = AesVectors(
        source="Wycheproof",
        source_desc="Test vectors for encryption and decryption.",
        source_url="https://github.com/C2SP/wycheproof/tree/master/testvectors",
        compliance=False,
        notes=data["notes"],
        mode=mode,
        keylen=128,
        encrypt=True,
        decrypt=True,
    )
    v192 = AesVectors(
        source="Wycheproof",
        source_desc="Resilience test vectors from Project Wycheproof",
        source_url="https://github.com/C2SP/wycheproof/tree/master/testvectors",
        compliance=False,
        notes=data["notes"],
        mode=mode,
        keylen=192,
        encrypt=True,
        decrypt=True,
    )
    v256 = AesVectors(
        source="Wycheproof",
        source_desc="Resilience test vectors from Project Wycheproof",
        source_url="https://github.com/C2SP/wycheproof/tree/master/testvectors",
        compliance=False,
        notes=data["notes"],
        mode=mode,
        keylen=256,
        encrypt=True,
        decrypt=True,
    )

    for group in data["testGroups"]:
        if group["keySize"] == 128:
            vectors = v128
        elif group["keySize"] == 192:
            vectors = v192
        else:
            vectors = v256

        for test in group["tests"]:
            aad = bytes.fromhex(test["aad"]) if "aad" in test else None
            tag = bytes.fromhex(test["tag"]) if "tag" in test else None
            vectors.tests.add(
                id=test["tcId"],
                type=test["result"],
                comment=test["comment"],
                flags=test["flags"],
                key=bytes.fromhex(test["key"]),
                pt=bytes.fromhex(test["msg"]),
                ct=bytes.fromhex(test["ct"]),
                iv=bytes.fromhex(test["iv"]),
                aad=aad,
                tag=tag,
            )

    out128 = pb2_dir / f"aes_wycheproof_{mode}_128.pb2"
    out192 = pb2_dir / f"aes_wycheproof_{mode}_192.pb2"
    out256 = pb2_dir / f"aes_wycheproof_{mode}_256.pb2"

    out128.write_bytes(v128.SerializeToString())
    out192.write_bytes(v192.SerializeToString())
    out256.write_bytes(v256.SerializeToString())


def generate_json() -> None:
    """Generates the JSON file categorizing test vectors."""
    pb2_dir = VECTORS_DIR / "pb2"
    vectors: dict[str, dict[int, list[str]]] = defaultdict(lambda: defaultdict(list))

    for file in pb2_dir.iterdir():
        _vec = AesVectors()
        _vec.ParseFromString(file.read_bytes())
        vectors[_vec.mode][_vec.keylen].append(file.name)

    out = VECTORS_DIR / "aes.json"
    with out.open("w") as fp:
        json.dump(vectors, fp, indent=2, sort_keys=True)


if __name__ == "__main__":
    pb2_dir = VECTORS_DIR / "pb2"
    pb2_dir.mkdir(exist_ok=True)

    cavp_files = generate_cavp_files()
    for k, files in cavp_files.items():
        mode, keylen = k
        parse_cavp(mode, keylen, files)

    gcm_decrypt_files = [(keylen, f"gcmDecrypt{keylen}.rsp") for keylen in KEY_LENGTHS]
    for klen, filename in gcm_decrypt_files:
        parse_cavp_gcm_decrypt(klen, filename)

    ccm_prefixes = ["VADT", "VPT", "VNT", "VTT"]
    ccm_files = [
        (klen, [f"{prefix}{str(klen)}.rsp" for prefix in ccm_prefixes])
        for klen in KEY_LENGTHS
    ]
    for klen, files in ccm_files:
        parse_cavp_ccm(klen, files)

    ccm_dvpt_files = [(klen, f"DVPT{str(klen)}.txt") for klen in KEY_LENGTHS]
    for klen, filename in ccm_dvpt_files:
        parse_cavp_ccm_dvpt(klen, filename)

    wp_files = ["aes_cbc_pkcs5_test.json", "aes_ccm_test.json", "aes_gcm_test.json"]
    for filename in wp_files:
        parse_wycheproof(filename)

    generate_json()

    imported_marker = VECTORS_DIR / "aes.imported"
    imported_marker.touch()
