"""Module to import NIST SHA1 test vectors.

.. caution::
    This module is intended for developers of this tool, as it's only used for
    testing and packaging, has hard-coded filenames, and uses relative paths.
"""

from pathlib import Path

from crypto_condor.vectors._sha.sha_pb2 import (
    ShakeMonteNistVectors,
    ShakeNistTest,
    ShakeNistVectors,
    ShakeVariableNistTest,
    ShakeVariableNistVectors,
    ShaMonteCarloNistVectors,
    ShaNistTest,
    ShaNistVectors,
)

VECTORS_DIR = Path("crypto_condor/vectors/_sha")


def import_vectors(src: str, dst: str):
    """Imports SHA test vectors.

    The file is parsed and serialized with
    :class:`crypto_condor.vectors._sha.sha_pb2.ShaNistVectors`.

    Args:
        src: The source filename.
        dst: The destination filename.
    """
    # WARN: hard-coded path.
    sha_dir = Path("crypto_condor/vectors/_sha")
    file = sha_dir / "rsp" / src
    data = file.read_text().split("\n")

    vectors = ShaNistVectors()
    vector: ShaNistTest

    vectors.filename = dst

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
        # No idea what this line is supposed to mean.
        if line.startswith("["):
            continue

        # All other lines should be data.
        key, value = line.split(" = ")
        match key:
            case "Len":
                vector = vectors.tests.add()
                vector.len = int(value)
            case "Msg":
                if vector.len == 0:  # If the message is empty, skip it.
                    continue
                setattr(vector, key.lower(), bytes.fromhex(value))
            case "MD":
                setattr(vector, key.lower(), bytes.fromhex(value))
            case _:
                raise ValueError("Unknown key %s" % key)

    file = sha_dir / "dat" / dst
    file.write_bytes(vectors.SerializeToString())


def import_monte_carlo_vectors(src: str, dst: str):
    """Imports SHA Monte-Carlo test vectors.

    The file is parsed and serialized with
    :class:`crypto_condor.vectors._sha.sha_pb2.ShaMonteCarloNistVectors`.

    Args:
        src: The source filename.
        dst: The destination filename.
    """
    # WARN: hard-coded path.
    sha_dir = Path("crypto_condor/vectors/_sha")
    file = sha_dir / "rsp" / src
    data = file.read_text().split("\n")

    vectors = ShaMonteCarloNistVectors()

    vectors.filename = dst

    count = 0

    while True:
        try:
            line = data.pop(0)
        except IndexError:
            break

        # Remove leading whitespace.
        line = line.rstrip()

        # Ignore comments and empty lines.
        if line.startswith("#") or not line:
            continue
        # No idea what this line is supposed to mean.
        if line.startswith("["):
            continue

        # All other lines should be data.
        key, value = line.split(" = ")
        match key:
            case "Seed":
                vectors.seed = bytes.fromhex(value)
            case "COUNT":
                count = int(value)
            case "MD":
                vectors.checkpoints[count] = bytes.fromhex(value)
            case _:
                raise ValueError("Unknown key %s" % key)

    file = sha_dir / "dat" / dst
    file.write_bytes(vectors.SerializeToString())


def import_shake_vectors(src: str, dst: str):
    """Imports SHAKE test vectors.

    The file is parsed and serialized with
    :class:`crypto_condor.vectors._sha.sha_pb2.ShakeNistVectors`.

    Args:
        src: The source filename.
        dst: The destination filename.
    """
    # WARN: hard-coded path.
    sha_dir = Path("crypto_condor/vectors/_sha")
    file = sha_dir / "rsp" / src
    data = file.read_text().split("\n")

    vectors = ShakeNistVectors()
    vector: ShakeNistTest

    vectors.filename = dst

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

        # This line specifies the output length of the XOF.
        if line.startswith("["):
            line = line.lstrip("[").rstrip().rstrip("]")
            key, value = line.split(" = ")
            vectors.output_len = int(value)
            continue

        # All other lines should be data.
        key, value = line.split(" = ")
        match key:
            case "Len":
                vector = vectors.tests.add()
                vector.len = int(value)
            case "Msg":
                if vector.len == 0:  # If the message is empty, skip it.
                    continue
                setattr(vector, key.lower(), bytes.fromhex(value))
            case "Output":
                setattr(vector, key.lower(), bytes.fromhex(value))
            case _:
                raise ValueError("Unknown key %s" % key)

    file = sha_dir / "dat" / dst
    file.write_bytes(vectors.SerializeToString())


def import_shake_monte_carlo_vectors(src: str, dst: str):
    """Imports SHAKE Monte-Carlo test vectors.

    The file is parsed and serialized with
    :class:`crypto_condor.vectors._sha.sha_pb2.ShakeMonteNistVectors`.

    Args:
        src: The source filename.
        dst: The destination filename.
    """
    # WARN: hard-coded path.
    sha_dir = Path("crypto_condor/vectors/_sha")
    file = sha_dir / "rsp" / src
    data = file.read_text().split("\n")

    vectors = ShakeMonteNistVectors()

    vectors.filename = dst

    count = 0

    while True:
        try:
            line = data.pop(0)
        except IndexError:
            break

        # Remove leading whitespace.
        line = line.rstrip()

        # Ignore comments and empty lines.
        if line.startswith("#") or not line:
            continue

        if line.startswith("["):
            line = line.lstrip("[").rstrip().rstrip("]")
            key, value = line.split(" = ")
            if "Minimum" in key:
                vectors.min_len = int(value)
            elif "Maximum" in key:
                vectors.max_len = int(value)
            continue

        # All other lines should be data.
        key, value = line.split(" = ")
        match key:
            case "Msg":
                vectors.msg = bytes.fromhex(value)
            case "COUNT":
                count = int(value)
            case "Output":
                vectors.checkpoints[count] = bytes.fromhex(value)
            case "Outputlen":
                # We ignore the output length to simplify the data structure.
                continue
            case _:
                raise ValueError("Unknown key %s" % key)

    file = sha_dir / "dat" / dst
    file.write_bytes(vectors.SerializeToString())


def import_shake_variable_vectors(src: str, dst: str):
    """Imports SHAKE variable output test vectors.

    The file is parsed and serialized with
    :class:`crypto_condor.vectors._sha.sha_pb2.ShakeVariableNistVectors`.

    Args:
        src: The source filename.
        dst: The destination filename.
    """
    # WARN: hard-coded path.
    sha_dir = Path("crypto_condor/vectors/_sha")
    file = sha_dir / "rsp" / src
    data = file.read_text().split("\n")

    vectors = ShakeVariableNistVectors()
    vector: ShakeVariableNistTest

    vectors.filename = dst

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
        if line.startswith("#") or line.startswith("[") or not line:
            continue

        # All other lines should be data.
        key, value = line.split(" = ")
        match key:
            case "COUNT":
                vector = vectors.tests.add()
                vector.count = int(value)
            case "Outputlen":
                vector.output_len = int(value)
            case "Msg" | "Output":
                setattr(vector, key.lower(), bytes.fromhex(value))
            case _:
                raise ValueError("Unknown key %s" % key)

    file = sha_dir / "dat" / dst
    file.write_bytes(vectors.SerializeToString())


def main():
    """Imports SHA test vectors."""
    dat_dir = VECTORS_DIR / "dat"
    dat_dir.mkdir(exist_ok=True)

    # ------------------------ SHA vectors --------------------------------
    files = [
        # SHA-1
        ("shabittestvectors/SHA1LongMsg.rsp", "sha1_bit_long.dat"),
        ("shabittestvectors/SHA1ShortMsg.rsp", "sha1_bit_short.dat"),
        ("shabytetestvectors/SHA1LongMsg.rsp", "sha1_byte_long.dat"),
        ("shabytetestvectors/SHA1ShortMsg.rsp", "sha1_byte_short.dat"),
        # SHA-224
        ("shabittestvectors/SHA224LongMsg.rsp", "sha224_bit_long.dat"),
        ("shabittestvectors/SHA224ShortMsg.rsp", "sha224_bit_short.dat"),
        ("shabytetestvectors/SHA224LongMsg.rsp", "sha224_byte_long.dat"),
        ("shabytetestvectors/SHA224ShortMsg.rsp", "sha224_byte_short.dat"),
        # SHA-256
        ("shabittestvectors/SHA256LongMsg.rsp", "sha256_bit_long.dat"),
        ("shabittestvectors/SHA256ShortMsg.rsp", "sha256_bit_short.dat"),
        ("shabytetestvectors/SHA256LongMsg.rsp", "sha256_byte_long.dat"),
        ("shabytetestvectors/SHA256ShortMsg.rsp", "sha256_byte_short.dat"),
        # SHA-384
        ("shabittestvectors/SHA384LongMsg.rsp", "sha384_bit_long.dat"),
        ("shabittestvectors/SHA384ShortMsg.rsp", "sha384_bit_short.dat"),
        ("shabytetestvectors/SHA384LongMsg.rsp", "sha384_byte_long.dat"),
        ("shabytetestvectors/SHA384ShortMsg.rsp", "sha384_byte_short.dat"),
        # SHA-512
        ("shabittestvectors/SHA512LongMsg.rsp", "sha512_bit_long.dat"),
        ("shabittestvectors/SHA512ShortMsg.rsp", "sha512_bit_short.dat"),
        ("shabytetestvectors/SHA512LongMsg.rsp", "sha512_byte_long.dat"),
        ("shabytetestvectors/SHA512ShortMsg.rsp", "sha512_byte_short.dat"),
        # SHA-512/224
        ("shabittestvectors/SHA512_224LongMsg.rsp", "sha512_224_bit_long.dat"),
        ("shabittestvectors/SHA512_224ShortMsg.rsp", "sha512_224_bit_short.dat"),
        ("shabytetestvectors/SHA512_224LongMsg.rsp", "sha512_224_byte_long.dat"),
        ("shabytetestvectors/SHA512_224ShortMsg.rsp", "sha512_224_byte_short.dat"),
        # SHA-512/256
        ("shabittestvectors/SHA512_256LongMsg.rsp", "sha512_256_bit_long.dat"),
        ("shabittestvectors/SHA512_256ShortMsg.rsp", "sha512_256_bit_short.dat"),
        ("shabytetestvectors/SHA512_256LongMsg.rsp", "sha512_256_byte_long.dat"),
        ("shabytetestvectors/SHA512_256ShortMsg.rsp", "sha512_256_byte_short.dat"),
        # SHA-3-224
        ("sha-3bittestvectors/SHA3_224LongMsg.rsp", "sha3_224_bit_long.dat"),
        ("sha-3bittestvectors/SHA3_224ShortMsg.rsp", "sha3_224_bit_short.dat"),
        ("sha-3bytetestvectors/SHA3_224LongMsg.rsp", "sha3_224_byte_long.dat"),
        ("sha-3bytetestvectors/SHA3_224ShortMsg.rsp", "sha3_224_byte_short.dat"),
        # SHA-3-256
        ("sha-3bittestvectors/SHA3_256LongMsg.rsp", "sha3_256_bit_long.dat"),
        ("sha-3bittestvectors/SHA3_256ShortMsg.rsp", "sha3_256_bit_short.dat"),
        ("sha-3bytetestvectors/SHA3_256LongMsg.rsp", "sha3_256_byte_long.dat"),
        ("sha-3bytetestvectors/SHA3_256ShortMsg.rsp", "sha3_256_byte_short.dat"),
        # SHA-3-384
        ("sha-3bittestvectors/SHA3_384LongMsg.rsp", "sha3_384_bit_long.dat"),
        ("sha-3bittestvectors/SHA3_384ShortMsg.rsp", "sha3_384_bit_short.dat"),
        ("sha-3bytetestvectors/SHA3_384LongMsg.rsp", "sha3_384_byte_long.dat"),
        ("sha-3bytetestvectors/SHA3_384ShortMsg.rsp", "sha3_384_byte_short.dat"),
        # SHA-3-512
        ("sha-3bittestvectors/SHA3_512LongMsg.rsp", "sha3_512_bit_long.dat"),
        ("sha-3bittestvectors/SHA3_512ShortMsg.rsp", "sha3_512_bit_short.dat"),
        ("sha-3bytetestvectors/SHA3_512LongMsg.rsp", "sha3_512_byte_long.dat"),
        ("sha-3bytetestvectors/SHA3_512ShortMsg.rsp", "sha3_512_byte_short.dat"),
    ]
    for src, dst in files:
        import_vectors(src, dst)

    # ------------------------ SHA Monte-Carlo vectors ---------------------------
    _hashes = [
        "SHA1",
        "SHA224",
        "SHA256",
        "SHA384",
        "SHA512",
        "SHA512_224",
        "SHA512_256",
    ]
    mct_files = [
        (f"sha{b}testvectors/{h}Monte.rsp", f"{h.lower()}_{b}_monte_carlo.dat")
        for h in _hashes
        for b in {"bit", "byte"}
    ]
    for src, dst in mct_files:
        import_monte_carlo_vectors(src, dst)

    # ------------------------ SHA-3 Monte-Carlo vectors ----------------------------
    sha3_mct_files = [
        (f"sha-3{b}testvectors/SHA3_{s}Monte.rsp", f"sha3_{s}_{b}_monte_carlo.dat")
        for b in {"bit", "byte"}
        for s in {"224", "256", "384", "512"}
    ]
    for src, dst in sha3_mct_files:
        import_monte_carlo_vectors(src, dst)

    # ------------------------ SHAKE vectors -----------------------------------------
    _d = {
        "LongMsg": "long",
        "ShortMsg": "short",
        "Monte": "monte",
        "VariableOut": "variable",
    }
    shake_files = [
        (f"shake{b}testvectors/SHAKE{s}{t}.rsp", f"shake{s}_{b}_{_d.get(t)}.dat")
        for b in {"bit", "byte"}
        for s in {"128", "256"}
        for t in _d.keys()
    ]
    for src, dst in shake_files:
        if "long" in dst or "short" in dst:
            import_shake_vectors(src, dst)
        elif "monte" in dst:
            import_shake_monte_carlo_vectors(src, dst)
        elif "variable" in dst:
            import_shake_variable_vectors(src, dst)
        else:
            raise ValueError(f"Wrong filename? {src} -> {dst}")

    vectors_dir = Path("crypto_condor/vectors/_sha")
    imported_marker = vectors_dir / "sha.imported"
    imported_marker.touch()


if __name__ == "__main__":
    main()
