"""Test vectors for ChaCha20."""

import strenum


class Mode(strenum.StrEnum):
    """Supported ChaCha20 modes of operation."""

    CHACHA20_POLY1305 = "CHACHA20-POLY1305"
    CHACHA20 = "CHACHA20"
