"""HMAC wrapper example.

Uses Python's built-in ``hmac`` module.

To test this example:

    crypto-condor-cli test wrapper HMAC hmac_wrapper_example.py
"""

import hmac


def CC_HMAC_digest_sha256(key: bytes, msg: bytes) -> bytes:
    """Tests HMAC-SHA-256 digest."""
    return hmac.digest(key, msg, "sha256")


def CC_HMAC_digest_sha3_512(key: bytes, msg: bytes) -> bytes:
    """Tests HMAC-SHA3-512 digest."""
    return hmac.digest(key, msg, "sha3_512")


def CC_HMAC_verify_sha256(key: bytes, msg: bytes, mac: bytes, mac_len: int) -> bool:
    """Tests HMAC-SHA-256 verify."""
    _mac = hmac.digest(key, msg, "sha256")
    # Some MACs are truncated, so we have to truncate ours to in order to compare them.
    ref_mac = _mac[:mac_len]
    return hmac.compare_digest(ref_mac, mac)


def CC_HMAC_verify_sha3_512(key: bytes, msg: bytes, mac: bytes, mac_len: int) -> bool:
    """Tests HMAC-SHA3-512 verify."""
    _mac = hmac.digest(key, msg, "sha3_512")
    # Some MACs are truncated, so we have to truncate ours to in order to compare them.
    ref_mac = _mac[:mac_len]
    return hmac.compare_digest(ref_mac, mac)
