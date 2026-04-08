"""HMAC harness example with Python's built-in module."""

import hmac


def CC_HMAC_verify_sha256(key: bytes, msg: bytes, mac: bytes) -> bytes:
    digest = hmac.digest(key, msg, "sha256")
    return hmac.compare_digest(digest, mac)


def CC_HMAC_verify_sha256_truncated(key: bytes, msg: bytes, mac: bytes) -> bytes:
    digest = hmac.digest(key, msg, "sha256")
    return hmac.compare_digest(digest[: len(mac)], mac)
