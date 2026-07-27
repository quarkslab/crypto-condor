"""Module to import ML-DSA test vectors.

.. caution::
    This module is intended for developers of this tool, as it's only used for
    testing and packaging, has hard-coded filenames, and uses relative paths.
"""

import copy
import json
from collections import defaultdict
from pathlib import Path

from crypto_condor.vectors._mldsa.mldsa_pb2 import MldsaVectors
from crypto_condor.vectors.wycheproof.models.mldsa_sign_noseed import (
    Model as MlDsaSignNoSeedModel,
)
from crypto_condor.vectors.wycheproof.models.mldsa_verify import (
    Model as MlDsaVerifyModel,
)

VECTORS_DIR = Path("crypto_condor/vectors/_mldsa")
FIPS204_DIR = VECTORS_DIR / "fips204"
WYCHEPROOF_DIR = VECTORS_DIR / "wycheproof"

WYCHEPROOF_SOURCE_URL = (
    "https://github.com/C2SP/wycheproof/tree/"
    "ee7b4f7e611928cbe163dc6f5e54527bfd166f34/testvectors_v1"
)

SIG_SIZE = {"ML-DSA-44": 2420, "ML-DSA-65": 3309, "ML-DSA-87": 4627}


def parse_nistkat(in_filename: str):
    """Parses vectors generated using NIST KAT generator."""
    # WARN: hard-coded path
    file = VECTORS_DIR / "nistkat" / in_filename

    blocks = file.read_text().split("\n\n")

    vectors = MldsaVectors()
    vectors.source = "NIST KAT"
    vectors.source_desc = (
        "Vectors generated with the reference implementation"
        " and the generator provided by NIST"
    )
    vectors.source_url = (
        "https://github.com/pq-crystals/dilithium/tree/master/ref/nistkat"
    )
    vectors.compliance = True
    match in_filename:
        case "PQCsignKAT_Dilithium2.rsp":
            vectors.paramset = "ML-DSA-44"
        case "PQCsignKAT_Dilithium3.rsp":
            vectors.paramset = "ML-DSA-65"
        case "PQCsignKAT_Dilithium5.rsp":
            vectors.paramset = "ML-DSA-87"
        case _:
            raise ValueError(f"Unsupported file {in_filename}")
    sig_size = SIG_SIZE[vectors.paramset]

    for block in blocks:
        block = block.strip()
        if not block or block.startswith("#"):
            continue

        test = vectors.tests.add()
        test.type = "valid"

        lines = block.split("\n")
        for line in lines:
            key, value = line.split(" = ")
            match key:
                case "count":
                    test.id = int(value) + 1
                case "msg" | "pk" | "sk":
                    setattr(test, key, bytes.fromhex(value))
                case "sm":
                    _sm = bytes.fromhex(value)
                    sig = _sm[:sig_size]
                    test.sig = sig
                case "seed":
                    # We don't store the seed.
                    pass
                case "mlen" | "smlen":
                    # We don't store the size of msg or sm, just compute it from
                    # the actual value when needed.
                    pass
                case _:
                    raise ValueError(f"Unknown key {key}")

    file = VECTORS_DIR / "pb2" / f"nistkat-{vectors.paramset}.pb2"
    file.write_bytes(vectors.SerializeToString())


def _load_fips204_json(
    category: str, paramset: str
) -> tuple[list[tuple[dict, dict]], list[dict]]:
    """Loads and merges all ML-DSA FIPS JSONs for a given category.

    Args:
        category: One of "keyGen", "sigGen", "sigVer".
        paramset: One of "ML-DSA-44", "ML-DSA-65", "ML-DSA-87".

    Returns:
        A tuple (merged_tests, test_groups) where merged_tests is a list of
        (test_dict, group_dict) tuples and test_groups is the list of all group dicts.
    """
    dir_name = f"ML-DSA-{category}-FIPS204"
    prompt_file = FIPS204_DIR / dir_name / "prompt.json"
    internal_file = FIPS204_DIR / dir_name / "internalProjection.json"
    results_file = FIPS204_DIR / dir_name / "expectedResults.json"

    with open(prompt_file) as f:
        prompt_data = json.load(f)
    with open(internal_file) as f:
        internal_data = json.load(f)
    with open(results_file) as f:
        results_data = json.load(f)

    merged = []
    for ptg in prompt_data["testGroups"]:
        if ptg["parameterSet"] != paramset:
            continue

        tgid = ptg["tgId"]

        itg = None
        for tg in internal_data["testGroups"]:
            if tg["tgId"] == tgid:
                itg = tg["tests"]
                break

        rtg = None
        for tg in results_data["testGroups"]:
            if tg["tgId"] == tgid:
                rtg = tg["tests"]
                break

        for pt in ptg["tests"]:
            tcid = pt["tcId"]
            for t in itg:
                if t["tcId"] == tcid:
                    pt.update(t)
            for t in rtg:
                if t["tcId"] == tcid:
                    pt.update(t)
            merged.append((pt, ptg))

    return merged, prompt_data["testGroups"]


def parse_fips204_keygen(paramset: str):
    """Parses keyGen vectors from FIPS 204 ACVP JSON.

    Args:
        paramset: One of "ML-DSA-44", "ML-DSA-65", "ML-DSA-87".
    """
    merged, _ = _load_fips204_json("keyGen", paramset)

    vectors = MldsaVectors()
    vectors.source = "NIST FIPS KAT"
    vectors.source_desc = "NIST ACVP test vectors for ML-DSA (FIPS 204)"
    vectors.source_url = "https://github.com/usnistgov/ACVP-Server/tree/v1.1.0.42/gen-val/json-files/ML-DSA-keyGen-FIPS204"
    vectors.compliance = True
    vectors.paramset = paramset
    vectors.category = "keyGen"

    for entry, _ in merged:
        test = vectors.tests.add()
        test.id = entry["tcId"]
        test.type = "valid"
        test.seed = bytes.fromhex(entry["seed"])
        test.pk = bytes.fromhex(entry["pk"])
        test.sk = bytes.fromhex(entry["sk"])

    out_file = VECTORS_DIR / "pb2" / f"fips204-keygen-{paramset}.pb2"
    out_file.write_bytes(vectors.SerializeToString())


def parse_fips204_siggen(paramset: str):
    """Parses sigGen vectors from FIPS 204 ACVP JSON.

    Creates separate pb2 files for pure and prehash variants.
    Only includes external interface tests.

    Args:
        paramset: One of "ML-DSA-44", "ML-DSA-65", "ML-DSA-87".
    """
    merged, _ = _load_fips204_json("sigGen", paramset)

    pure_vectors = MldsaVectors()
    pure_vectors.source = "NIST FIPS KAT"
    pure_vectors.source_desc = "NIST ACVP test vectors for ML-DSA (FIPS 204)"
    pure_vectors.source_url = "https://github.com/usnistgov/ACVP-Server/tree/v1.1.0.42/gen-val/json-files/ML-DSA-sigGen-FIPS204"
    pure_vectors.compliance = True
    pure_vectors.paramset = paramset
    pure_vectors.category = "sigGen"
    pure_vectors.prehash = False

    prehash_vectors = copy.deepcopy(pure_vectors)
    prehash_vectors.prehash = True

    for entry, group in merged:
        # Filter: only external interface
        if group.get("signatureInterface", "external") != "external":
            continue
        if group.get("externalMu", False):
            continue

        is_prehash = group.get("preHash", "pure") == "preHash"
        vectors = prehash_vectors if is_prehash else pure_vectors

        test = vectors.tests.add()
        test.id = entry["tcId"]
        test.type = "valid"
        test.pk = bytes.fromhex(entry["pk"])
        test.msg = bytes.fromhex(entry["message"])
        test.ctx = bytes.fromhex(entry["context"])

        test.sk = bytes.fromhex(entry["sk"])

        if "rnd" in entry:
            test.rnd = bytes.fromhex(entry["rnd"])
        else:
            test.rnd = bytes.fromhex("00" * 32)

        test.deterministic = group.get("deterministic", False)
        test.preHash = is_prehash
        test.signatureInterface = group.get("signatureInterface", "external")
        test.externalMu = group.get("externalMu", False)
        test.hashAlg = entry.get("hashAlg", "")

        test.sig = bytes.fromhex(entry["signature"])

    pure_out = VECTORS_DIR / "pb2" / f"fips204-siggen-{paramset}.pb2"
    pure_out.write_bytes(pure_vectors.SerializeToString())

    prehash_out = VECTORS_DIR / "pb2" / f"fips204-siggen-{paramset}_prehash.pb2"
    prehash_out.write_bytes(prehash_vectors.SerializeToString())


def parse_fips204_sigver(paramset: str):
    """Parses sigVer vectors from FIPS 204 ACVP JSON.

    Creates separate pb2 files for pure and prehash variants.
    Only includes external interface tests.

    Args:
        paramset: One of "ML-DSA-44", "ML-DSA-65", "ML-DSA-87".
    """
    merged, _ = _load_fips204_json("sigVer", paramset)

    pure_vectors = MldsaVectors()
    pure_vectors.source = "NIST FIPS KAT"
    pure_vectors.source_desc = "NIST ACVP test vectors for ML-DSA (FIPS 204)"
    pure_vectors.source_url = "https://github.com/usnistgov/ACVP-Server/tree/v1.1.0.42/gen-val/json-files/ML-DSA-sigVer-FIPS204"
    pure_vectors.compliance = True
    pure_vectors.paramset = paramset
    pure_vectors.category = "sigVer"
    pure_vectors.prehash = False

    prehash_vectors = copy.deepcopy(pure_vectors)
    prehash_vectors.prehash = True

    for entry, group in merged:
        # Filter: only external interface
        if group.get("signatureInterface", "external") != "external":
            continue
        if group.get("externalMu", False):
            continue

        is_prehash = group.get("preHash", "pure") == "preHash"
        vectors = prehash_vectors if is_prehash else pure_vectors

        test = vectors.tests.add()
        test.id = entry["tcId"]
        test.type = "valid" if entry["testPassed"] else "invalid"
        test.pk = bytes.fromhex(entry["pk"])
        test.msg = bytes.fromhex(entry["message"])
        test.ctx = bytes.fromhex(entry["context"])

        test.sig = bytes.fromhex(entry["signature"])

        test.preHash = is_prehash
        test.signatureInterface = group.get("signatureInterface", "external")
        test.externalMu = group.get("externalMu", False)
        test.hashAlg = entry.get("hashAlg", "")

    pure_out = VECTORS_DIR / "pb2" / f"fips204-sigver-{paramset}.pb2"
    pure_out.write_bytes(pure_vectors.SerializeToString())

    prehash_out = VECTORS_DIR / "pb2" / f"fips204-sigver-{paramset}_prehash.pb2"
    prehash_out.write_bytes(prehash_vectors.SerializeToString())


def parse_wycheproof_sign_noseed(paramset: str):
    """Parses sign (noseed) vectors from Wycheproof.

    Uses pydantic models for JSON validation.

    Args:
        paramset: One of "ML-DSA-44", "ML-DSA-65", "ML-DSA-87".
    """
    ps_lower = paramset.lower().replace("-", "_").replace("ml_dsa", "mldsa")
    in_file = WYCHEPROOF_DIR / f"{ps_lower}_sign_noseed_test.json"

    model = MlDsaSignNoSeedModel.model_validate_json(in_file.read_text())

    vectors = MldsaVectors()
    vectors.source = "Wycheproof"
    vectors.source_desc = "Wycheproof ML-DSA sign (noseed) test vectors"
    vectors.source_url = WYCHEPROOF_SOURCE_URL
    vectors.compliance = False
    vectors.paramset = paramset
    vectors.category = "sigGen"
    vectors.prehash = False

    for group in model.testGroups:
        for test in group.tests:
            # Skip External mu
            if "Internal" in test.flags:
                continue

            t = vectors.tests.add()
            t.id = test.tcId
            t.type = test.result.value
            t.comment = test.comment
            t.flags.extend(test.flags)

            t.msg = bytes.fromhex(test.msg)

            if group.publicKey is not None:
                t.pk = bytes.fromhex(group.publicKey)

            t.sk = bytes.fromhex(group.privateKey)

            if test.ctx is not None:
                t.ctx = bytes.fromhex(test.ctx)

            t.sig = bytes.fromhex(test.sig)

            if test.rnd is not None:
                t.rnd = bytes.fromhex(test.rnd)
                t.deterministic = False
            else:
                t.deterministic = True

            t.externalMu = False
            t.signatureInterface = "external"
            t.hashAlg = ""

    out_file = VECTORS_DIR / "pb2" / f"wycheproof-sign-noseed-{paramset}.pb2"
    out_file.write_bytes(vectors.SerializeToString())


def parse_wycheproof_verify(paramset: str):
    """Parses verify vectors from Wycheproof.

    Uses pydantic models for JSON validation.

    Args:
        paramset: One of "ML-DSA-44", "ML-DSA-65", "ML-DSA-87".
    """
    ps_lower = paramset.lower().replace("-", "_").replace("ml_dsa", "mldsa")
    in_file = WYCHEPROOF_DIR / f"{ps_lower}_verify_test.json"

    model = MlDsaVerifyModel.model_validate_json(in_file.read_text())

    vectors = MldsaVectors()
    vectors.source = "Wycheproof"
    vectors.source_desc = "Wycheproof ML-DSA verify test vectors"
    vectors.source_url = WYCHEPROOF_SOURCE_URL
    vectors.compliance = False
    vectors.paramset = paramset
    vectors.category = "sigVer"
    vectors.prehash = False

    for group in model.testGroups:
        for test in group.tests:
            t = vectors.tests.add()
            t.id = test.tcId
            t.type = test.result.value
            t.comment = test.comment
            t.flags.extend(test.flags)

            t.msg = bytes.fromhex(test.msg)
            t.pk = bytes.fromhex(group.publicKey)

            if test.ctx is not None:
                t.ctx = bytes.fromhex(test.ctx)

            t.sig = bytes.fromhex(test.sig)

            t.externalMu = False
            t.signatureInterface = "external"
            t.hashAlg = ""

    out_file = VECTORS_DIR / "pb2" / f"wycheproof-verify-{paramset}.pb2"
    out_file.write_bytes(vectors.SerializeToString())


def generate_json() -> None:
    """Generates the JSON file categorizing test vectors."""
    pb2_dir = VECTORS_DIR / "pb2"
    vectors: dict[str, list[str]] = defaultdict(list)

    for file in sorted(pb2_dir.iterdir()):
        if file.name == ".gitkeep":
            continue
        _vec = MldsaVectors()
        _vec.ParseFromString(file.read_bytes())
        vectors[_vec.paramset].append(file.name)

    out = VECTORS_DIR / "mldsa.json"
    with out.open("w") as fp:
        json.dump(vectors, fp, indent=4, sort_keys=True)


if __name__ == "__main__":
    pb2_dir = VECTORS_DIR / "pb2"
    pb2_dir.mkdir(exist_ok=True)

    nistkat_files = [
        "PQCsignKAT_Dilithium2.rsp",
        "PQCsignKAT_Dilithium3.rsp",
        "PQCsignKAT_Dilithium5.rsp",
    ]
    for filename in nistkat_files:
        parse_nistkat(filename)

    paramsets = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
    for paramset in paramsets:
        parse_fips204_keygen(paramset)
        parse_fips204_siggen(paramset)
        parse_fips204_sigver(paramset)

        parse_wycheproof_sign_noseed(paramset)
        parse_wycheproof_verify(paramset)

    generate_json()

    imported_marker = VECTORS_DIR / "mldsa.imported"
    imported_marker.touch()
