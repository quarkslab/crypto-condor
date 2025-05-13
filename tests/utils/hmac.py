"""Test utils for HMAC."""

import hmac
import random


def generate_hmac_output(algo: str, digest_size: int, valid: bool) -> str:
    """Generates 15 test cases of HMAC output.

    Args:
        algo:
            The hash function to use with HMAC.
        digest_size:
            The size of the digest in bytes. It is used to determine the size of the
            keys that are generated.
        valid:
            Whether the output should be valid HMAC tags or not.

    Returns:
        A string of correctly formatted output.
    """
    output = f"# Test correct output for {algo}\n"

    for _ in range(5):
        key = random.randbytes(digest_size)
        msg = random.randbytes(72)
        if valid:
            tag = hmac.digest(key, msg, algo)
        else:
            tag = random.randbytes(digest_size)
        output += f"{key.hex()}/{msg.hex()}/{tag.hex()}\n"

    # Short keys
    for _ in range(5):
        key = random.randbytes(digest_size // 2)
        msg = random.randbytes(72)
        if valid:
            tag = hmac.digest(key, msg, algo)
        else:
            tag = random.randbytes(digest_size)
        output += f"{key.hex()}/{msg.hex()}/{tag.hex()}\n"

    # Long keys
    for _ in range(5):
        key = random.randbytes(digest_size * 2)
        msg = random.randbytes(72)
        if valid:
            tag = hmac.digest(key, msg, algo)
        else:
            tag = random.randbytes(digest_size)
        output += f"{key.hex()}/{msg.hex()}/{tag.hex()}\n"

    return output
