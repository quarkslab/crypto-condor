"""Module to import NIST AES test vectors.

.. caution::
    This module is intended for developers of this tool, as it's only used for
    testing and packaging, has hard-coded filenames, and uses relative paths.
    For use within the Makefile, ``cd`` to the corresponding directory first.
"""

import re
from pathlib import Path
from typing import List, Tuple

from crypto_condor.vectors._aes.aes_pb2 import AesNistVectors

VECTORS_DIR = Path("crypto_condor/vectors/_aes")


def get_aes_vectors() -> List[Tuple[str, str, str, bool]]:
    """Returns a list of tuples with all AES test vectors to import.

    The tuples contain the input filename, the output filename, a name for
    AesNistVectors, and whether the file contains test vectors for encryption.

    This last parameter indicates that the importer should assume that all test
    vectors are for encryption, until they encounter a [DECRYPT] header, if any.
    """
    ecb_test_vectors = [
        ("ECBGFSbox128.rsp", "aes_ecb_128_gfsbox.dat", "ECB 128 GFSBox", True),
        ("ECBGFSbox192.rsp", "aes_ecb_192_gfsbox.dat", "ECB 192 GFSBox", True),
        ("ECBGFSbox256.rsp", "aes_ecb_256_gfsbox.dat", "ECB 256 GFSBox", True),
        ("ECBKeySbox128.rsp", "aes_ecb_128_keysbox.dat", "ECB 128 KeySbox", True),
        ("ECBKeySbox192.rsp", "aes_ecb_192_keysbox.dat", "ECB 192 KeySbox", True),
        ("ECBKeySbox256.rsp", "aes_ecb_256_keysbox.dat", "ECB 256 KeySbox", True),
        ("ECBVarKey128.rsp", "aes_ecb_128_varkey.dat", "ECB 128 VarKey", True),
        ("ECBVarKey192.rsp", "aes_ecb_192_varkey.dat", "ECB 192 VarKey", True),
        ("ECBVarKey256.rsp", "aes_ecb_256_varkey.dat", "ECB 256 VarKey", True),
        ("ECBVarTxt128.rsp", "aes_ecb_128_txt.dat", "ECB 128 VarTxt", True),
        ("ECBVarTxt192.rsp", "aes_ecb_192_txt.dat", "ECB 192 VarTxt", True),
        ("ECBVarTxt256.rsp", "aes_ecb_256_txt.dat", "ECB 256 VarTxt", True),
    ]

    ecb_mmt_test_vectors = [
        ("ECBMMT128.rsp", "aes_ecb_128_mmt.dat", "ECB 128 MMT", True),
        ("ECBMMT192.rsp", "aes_ecb_192_mmt.dat", "ECB 192 MMT", True),
        ("ECBMMT256.rsp", "aes_ecb_256_mmt.dat", "ECB 256 MMT", True),
    ]

    cbc_test_vectors = [
        ("CBCGFSbox128.rsp", "aes_cbc_128_gfsbox.dat", "CBC 128 GFSBox", True),
        ("CBCGFSbox192.rsp", "aes_cbc_192_gfsbox.dat", "CBC 192 GFSBox", True),
        ("CBCGFSbox256.rsp", "aes_cbc_256_gfsbox.dat", "CBC 256 GFSBox", True),
        ("CBCKeySbox128.rsp", "aes_cbc_128_keysbox.dat", "CBC 128 KeySbox", True),
        ("CBCKeySbox192.rsp", "aes_cbc_192_keysbox.dat", "CBC 192 KeySbox", True),
        ("CBCKeySbox256.rsp", "aes_cbc_256_keysbox.dat", "CBC 256 KeySbox", True),
        ("CBCVarKey128.rsp", "aes_cbc_128_varkey.dat", "CBC 128 VarKey", True),
        ("CBCVarKey192.rsp", "aes_cbc_192_varkey.dat", "CBC 192 VarKey", True),
        ("CBCVarKey256.rsp", "aes_cbc_256_varkey.dat", "CBC 256 VarKey", True),
        ("CBCVarTxt128.rsp", "aes_cbc_128_txt.dat", "CBC 128 VarTxt", True),
        ("CBCVarTxt192.rsp", "aes_cbc_192_txt.dat", "CBC 192 VarTxt", True),
        ("CBCVarTxt256.rsp", "aes_cbc_256_txt.dat", "CBC 256 VarTxt", True),
    ]

    cbc_mmt_test_vectors = [
        ("CBCMMT128.rsp", "aes_cbc_128_mmt.dat", "CBC 128 MMT", True),
        ("CBCMMT192.rsp", "aes_cbc_192_mmt.dat", "CBC 192 MMT", True),
        ("CBCMMT256.rsp", "aes_cbc_256_mmt.dat", "CBC 256 MMT", True),
    ]

    # CFB1 test vectors aren't included as the 1-byte plaintext is not supported
    # by pycryptodome.
    cfb_test_vectors = [
        ("CFB8GFSbox128.rsp", "aes_cfb8_128_gfsbox.dat", "CFB8 128 GFSBox", True),
        ("CFB8GFSbox192.rsp", "aes_cfb8_192_gfsbox.dat", "CFB8 192 GFSBox", True),
        ("CFB8GFSbox256.rsp", "aes_cfb8_256_gfsbox.dat", "CFB8 256 GFSBox", True),
        ("CFB8KeySbox128.rsp", "aes_cfb8_128_keysbox.dat", "CFB8 128 KeySbox", True),
        ("CFB8KeySbox192.rsp", "aes_cfb8_192_keysbox.dat", "CFB8 192 KeySbox", True),
        ("CFB8KeySbox256.rsp", "aes_cfb8_256_keysbox.dat", "CFB8 256 KeySbox", True),
        ("CFB8VarKey128.rsp", "aes_cfb8_128_varkey.dat", "CFB8 128 VarKey", True),
        ("CFB8VarKey192.rsp", "aes_cfb8_192_varkey.dat", "CFB8 192 VarKey", True),
        ("CFB8VarKey256.rsp", "aes_cfb8_256_varkey.dat", "CFB8 256 VarKey", True),
        ("CFB8VarTxt128.rsp", "aes_cfb8_128_txt.dat", "CFB8 128 VarTxt", True),
        ("CFB8VarTxt192.rsp", "aes_cfb8_192_txt.dat", "CFB8 192 VarTxt", True),
        ("CFB8VarTxt256.rsp", "aes_cfb8_256_txt.dat", "CFB8 256 VarTxt", True),
        ("CFB128GFSbox128.rsp", "aes_cfb128_128_gfsbox.dat", "CFB128 128 GFSBox", True),
        ("CFB128GFSbox192.rsp", "aes_cfb128_192_gfsbox.dat", "CFB128 192 GFSBox", True),
        ("CFB128GFSbox256.rsp", "aes_cfb128_256_gfsbox.dat", "CFB128 256 GFSBox", True),
        (
            "CFB128KeySbox128.rsp",
            "aes_cfb128_128_keysbox.dat",
            "CFB128 128 KeySbox",
            True,
        ),
        (
            "CFB128KeySbox192.rsp",
            "aes_cfb128_192_keysbox.dat",
            "CFB128 192 KeySbox",
            True,
        ),
        (
            "CFB128KeySbox256.rsp",
            "aes_cfb128_256_keysbox.dat",
            "CFB128 256 KeySbox",
            True,
        ),
        ("CFB128VarKey128.rsp", "aes_cfb128_128_varkey.dat", "CFB128 128 VarKey", True),
        ("CFB128VarKey192.rsp", "aes_cfb128_192_varkey.dat", "CFB128 192 VarKey", True),
        ("CFB128VarKey256.rsp", "aes_cfb128_256_varkey.dat", "CFB128 256 VarKey", True),
        ("CFB128VarTxt128.rsp", "aes_cfb128_128_txt.dat", "CFB128 128 VarTxt", True),
        ("CFB128VarTxt192.rsp", "aes_cfb128_192_txt.dat", "CFB128 192 VarTxt", True),
        ("CFB128VarTxt256.rsp", "aes_cfb128_256_txt.dat", "CFB128 256 VarTxt", True),
    ]

    cfb_mmt_test_vectors = [
        ("CFB8MMT128.rsp", "aes_cfb8_128_mmt.dat", "CFB8 128 MMT", True),
        ("CFB8MMT192.rsp", "aes_cfb8_192_mmt.dat", "CFB8 192 MMT", True),
        ("CFB8MMT256.rsp", "aes_cfb8_256_mmt.dat", "CFB8 256 MMT", True),
        ("CFB128MMT128.rsp", "aes_cfb128_128_mmt.dat", "CFB128 128 MMT", True),
        ("CFB128MMT192.rsp", "aes_cfb128_192_mmt.dat", "CFB128 192 MMT", True),
        ("CFB128MMT256.rsp", "aes_cfb128_256_mmt.dat", "CFB128 256 MMT", True),
    ]

    ctr_test_vectors = [
        ("CTR128.rsp", "aes_ctr_128.dat", "CTR 128", True),
        ("CTR192.rsp", "aes_ctr_192.dat", "CTR 192", True),
        ("CTR256.rsp", "aes_ctr_256.dat", "CTR 256", True),
    ]

    gcm_test_vectors = [
        ("gcmEncryptExtIV128.rsp", "aes_gcm_128_enc.dat", "GCM 128 enc", True),
        ("gcmEncryptExtIV192.rsp", "aes_gcm_192_enc.dat", "GCM 192 enc", True),
        ("gcmEncryptExtIV256.rsp", "aes_gcm_256_enc.dat", "GCM 256 enc", True),
        ("gcmDecrypt128.rsp", "aes_gcm_128_dec.dat", "GCM 128 dec", False),
        ("gcmDecrypt192.rsp", "aes_gcm_192_dec.dat", "GCM 192 dec", False),
        ("gcmDecrypt256.rsp", "aes_gcm_256_dec.dat", "GCM 256 dec", False),
    ]

    aes_vectors = list()
    aes_vectors.extend(ecb_test_vectors)
    aes_vectors.extend(ecb_mmt_test_vectors)
    aes_vectors.extend(cbc_test_vectors)
    aes_vectors.extend(cbc_mmt_test_vectors)
    aes_vectors.extend(cfb_test_vectors)
    aes_vectors.extend(cfb_mmt_test_vectors)
    aes_vectors.extend(ctr_test_vectors)
    aes_vectors.extend(gcm_test_vectors)

    return aes_vectors


def import_aes_file(in_file: str, out_file: str, name: str, encrypt: bool = True):
    """Imports a file of AES test vectors to a protobuf-based class.

    Args:
        in_file:
            The name of the file containing the test vectors.
        out_file:
            The name of the file to which the serialized data is written.
        name:
            The name of the group of test vectors.
        encrypt:
            Whether the test should encrypt or decrypt the data.

    Notes:
        This is meant for developers of the tool to parse NIST .rsp vectors to
        protobuf serialized data. From the filenames paths are constructed by
        prepending the directory <path-to-vectors>/nist/aes, where path-to-vectors is
        a relative path to the resource directory containing the test vectors.
    """
    test_vectors = AesNistVectors()

    # WARN: hard-coded prefix.
    vectors_dir = Path("crypto_condor/vectors/_aes")
    rsp = vectors_dir / "rsp" / in_file
    dat = vectors_dir / "dat" / out_file

    with rsp.open("r") as file:
        data = file.readlines()

    test_vectors.name = name
    # We can get the mode and key length from the name.
    split_name = name.split(" ")
    test_vectors.mode = split_name[0]
    test_vectors.key_length = int(split_name[1])

    i = 0
    tv = None
    new_group = True
    count = 1

    while i < len(data) - 1:
        i += 1
        line = data[i]
        line = line.strip()

        if line.startswith("#"):
            continue

        if not line:
            tv = None
            new_group = True
            continue

        if line.startswith("["):
            if line == "[DECRYPT]":
                encrypt = False
            continue

        if new_group:
            tv = test_vectors.tests.add()
            tv.is_valid = True  # Vector is valid by default
            tv.encrypt = encrypt
            new_group = False

        res = re.match("([A-Za-z0-9]+) = ?(.*)", line)
        if not res:
            if line == "FAIL":
                tv.is_valid = False
            continue

        k = res.group(1).lower()
        v = res.group(2).lower()

        # Keys aren't consistent between test vector files
        if k == "ct":
            k = "ciphertext"
        if k == "pt":
            k = "plaintext"

        try:
            if k == "count":
                setattr(tv, k, int(v))
                tv.id = count
                count += 1
                tv.line_number = i + 1
            else:
                setattr(tv, k, v)
        except Exception as error:
            print(f"line: {i}")
            print(f"content: {line}")
            print(f"error: {error}")
            exit(1)

    with dat.open("wb") as file:
        file.write(test_vectors.SerializeToString())


def main():
    """Imports all AES test vectors."""
    dat_dir = VECTORS_DIR / "dat"
    dat_dir.mkdir(exist_ok=True)

    vectors = get_aes_vectors()
    for vector in vectors:
        import_aes_file(*vector)

    vectors_dir = Path("crypto_condor/vectors/_aes")
    imported_marker = vectors_dir / "aes.imported"
    imported_marker.touch()


if __name__ == "__main__":
    main()
