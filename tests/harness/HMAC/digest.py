"""HMAC harness example with Python's built-in module."""

import hmac


def CC_HMAC_digest_sha256(key: bytes, msg: bytes) -> bytes:
    digest = hmac.digest(key, msg, "sha256")
    return digest
