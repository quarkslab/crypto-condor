# NIST AES test vectors

Test vectors for ECB, CBC, CFB8, and CFB128 are those provided by the
[NIST CAVP website](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers#AES).
They were downloaded on April 13, 2023 as:
https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/KAT_AES.zip.

GCM test vectors downloaded on May 3, 2023 from:
https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip.

CTR test vectors were taken from
[RFC 3686](https://datatracker.ietf.org/doc/html/rfc3686.html#section-6)
and adapted to NIST's `.rsp` format so that they could be parsed with the same
function.

