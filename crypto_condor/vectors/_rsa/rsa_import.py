"""Module to import NIST RSA test vectors.

.. caution::
    This module is intended for developers of this tool, as it's only used for
    testing and packaging, has hard-coded filenames, and uses relative paths.
"""

import shutil
from pathlib import Path

from crypto_condor.vectors._rsa.rsa_pb2 import (
    RsaNistSigGenTest,
    RsaNistSigGenVectors,
    RsaNistSigVerTest,
    RsaNistSigVerVectors,
)

VECTORS_DIR = Path("crypto_condor/vectors/_rsa")


def _norm_sha(sha: str) -> str:
    match sha.lower():
        case "sha512224":
            return "sha512_224"
        case "sha512256":
            return "sha512_256"
        case _:
            return sha.lower()


def import_siggen_vectors(src: str, scheme: str):
    """Imports RSA test vectors.

    Imports both PKCS#1 v1.5 and PSS vectors.

    The file is parsed and serialized with
    :class:`crypto_condor.vectors._rsa.rsa_pb2.RsaNistSigGenVectors`.

    Args:
        src:
            The name of the test vectors file.
        scheme:
            The scheme name, as written in the resulting files. Either
            'signature' or 'pss'.
    """
    # WARN: hard-coded path.
    rsa_dir = Path("crypto_condor/vectors/_rsa")
    file = rsa_dir / "rsp" / src
    data = file.read_text().split("\n")

    vectors: RsaNistSigGenVectors | None = None
    vector: RsaNistSigGenTest

    sha = ""
    mod = 0
    n = ""
    e = ""
    d = ""
    dst = ""

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

        # All other lines should be data.
        key, value = line.split(" = ")
        match key:
            case "[mod":
                line = line.lstrip("[").rstrip().rstrip("]")
                if mod != 0:  # Write the last section that used the previous modulus
                    dst = rsa_dir / f"dat/rsa_{scheme}_{str(mod)}_{sha}.dat"
                    vectors.filename = dst.name
                    dst.write_bytes(vectors.SerializeToString())
                    # Since we are already writing the vectors, set to None to
                    # avoid repeating the operation in the SHAAlg case.
                    vectors = None
                mod = int(line.split(" = ")[-1])
            case "n":
                n = value
            case "e":
                e = value
            case "d":
                d = value
            case "SHAAlg":
                # If the hash changes, then write old vectors and instantiate new ones.
                if _norm_sha(value) != sha:
                    if vectors is not None:
                        dst = rsa_dir / f"dat/rsa_{scheme}_{str(mod)}_{sha}.dat"
                        vectors.filename = dst.name
                        dst.write_bytes(vectors.SerializeToString())
                    vectors = RsaNistSigGenVectors()
                    vectors.mod = mod
                    vectors.n = n
                    vectors.e = e
                    vectors.d = d
                    sha = _norm_sha(value)
                # Each test starts with SHAAlg, so instantiate a new test.
                vector = vectors.tests.add()
                vector.alg = value
            case "Msg":
                vector.msg = value
            case "S":
                vector.sig = value
            case "SaltVal":
                # Skip for now: neither PyCryptodome or cryptography seem to
                # accept this value for testing.
                continue
            case _:
                raise ValueError("Unknown key %s" % key)

    dst = rsa_dir / f"dat/rsa_{scheme}_{str(mod)}_{sha.lower()}.dat"
    dst.write_bytes(vectors.SerializeToString())


def import_sigver_vectors(src: str, scheme: str):
    """Imports RSA test vectors.

    Imports both PKCS#1 v1.5 and PSS vectors.

    The file is parsed and serialized with
    :class:`crypto_condor.vectors._rsa.rsa_pb2.RsaNistSigVerVectors`.

    Args:
        src:
            The name of the test vectors file.
        scheme:
            The scheme name, as written in the resulting files. Either
            'signature' or 'pss'.
    """
    # WARN: hard-coded path.
    rsa_dir = Path("crypto_condor/vectors/_rsa")
    file = rsa_dir / "rsp" / src
    data = file.read_text().split("\n")

    vectors: RsaNistSigVerVectors | None = None
    vector: RsaNistSigVerTest

    # For some reason there are various groups of non-consecutive tests for the
    # same SHA and modulus, so we count them to use the counter for the filename.
    count = 0

    sha = ""
    mod = 0
    n = ""
    p = ""
    q = ""
    dst = ""

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

        # Some lines have a modified EM and some of those DON'T have the space
        # right after the equals sign. Since we don't currently use that, just
        # skip it.
        if line.startswith("EM"):
            continue

        # All other lines should be data.
        key, value = line.split(" = ")
        match key:
            case "[mod":
                line = line.lstrip("[").rstrip().rstrip("]")
                if mod != 0:  # Write the last section that used the previous modulus
                    dst = rsa_dir / f"dat/rsa_ver_{scheme}_{str(mod)}_{sha}_{count}.dat"
                    vectors.id = count
                    dst.write_bytes(vectors.SerializeToString())
                    # Since we are already writing the vectors, set to None to
                    # avoid repeating the operation in the SHAAlg case.
                    vectors = None
                mod = int(line.split(" = ")[-1])
                # Reset counter
                count = 0
            case "n":
                n = value
            case "p":
                p = value
            case "q":
                q = value
            case "SHAAlg":
                # If the hash changes, then write old vectors.
                if _norm_sha(value) != sha:
                    if vectors is not None:
                        dst = (
                            rsa_dir
                            / f"dat/rsa_ver_{scheme}_{str(mod)}_{sha}_{count}.dat"
                        )
                        vectors.id = count
                        dst.write_bytes(vectors.SerializeToString())
                    sha = _norm_sha(value)
                    # SHA1 or SHA-512/224 means we've completed the group.
                    if sha == "sha1" or sha == "sha512_224":
                        count += 1
                    vectors = RsaNistSigVerVectors()
                    vectors.mod = mod
                    vectors.n = n
                    vectors.p = p
                    vectors.q = q
                    vectors.sha = sha
                # Each test starts with SHAAlg, so instantiate a new test.
                vector = vectors.tests.add()
            case "e" | "d":
                setattr(vector, key, value)
            case "Msg":
                # Pad with 1 zero if length is not even.
                if len(value) % 2 != 0:
                    value = "0" + value
                vector.msg = value
            case "S":
                # Pad with 1 zero if length is not even.
                if len(value) % 2 != 0:
                    value = "0" + value
                vector.sig = value
            case "Result":
                if value.startswith("P"):  # Valid test, no reason to add.
                    vector.result = True
                    continue
                vector.result = False
                if scheme == "signature":  # signature vectors don't have reasons.
                    continue
                _, reason = value.split(" (")
                # Remove trailing parentheses, newline, and whitespace.
                reason = reason.rstrip(")\n").rstrip()
                # Remove reason number.
                _, reason = reason.split(" - ", 1)
                vector.reason = reason.rstrip()
            case "SaltVal":
                if value.rstrip() != "00":  # Null salt is represented by 00.
                    vector.salt = value
            case _:
                raise ValueError("Unknown key %s" % key)

    dst = rsa_dir / f"dat/rsa_ver_{scheme}_{str(mod)}_{sha}_{count}.dat"
    dst.write_bytes(vectors.SerializeToString())


if __name__ == "__main__":
    # Ensure that the directory starts anew.
    dat_dir = VECTORS_DIR / "dat"
    # Ignore errors since the directory may not exist in the repo.
    shutil.rmtree(dat_dir, ignore_errors=True)
    dat_dir.mkdir()

    sig_gen_files = [
        ("SigGen15_186-3.txt", "signature"),
        ("SigGen15_186-3_TruncatedSHAs.txt", "signature"),
        ("SigGenPSS_186-3.txt", "pss"),
        ("SigGenPSS_186-3_TruncatedSHAs.txt", "pss"),
    ]
    for src, scheme in sig_gen_files:
        import_siggen_vectors(src, scheme)

    sig_ver_files = [
        ("SigVer15_186-3.rsp", "signature"),
        ("SigVer15_186-3_TruncatedSHAs.rsp", "signature"),
        ("SigVerPSS_186-3.rsp", "pss"),
        ("SigVerPSS_186-3_TruncatedSHAs.rsp", "pss"),
    ]
    for src, scheme in sig_ver_files:
        import_sigver_vectors(src, scheme)
    vectors_dir = Path("crypto_condor/vectors/_rsa")
    imported_marker = vectors_dir / "rsa.imported"
    imported_marker.touch()
