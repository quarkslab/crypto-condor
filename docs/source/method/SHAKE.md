# SHAKE

{{ prolog }}

SHAKE are extendable-output functions from the
[KECCAK](https://keccak.team/keccak.html) family.

## Overview

Standardised in [FIPS 202][FIPS202], SHAKE128 and SHAKE256 are two algorithms
from the KECCAK family. They are based on a [sponge construction][SPONGE]. As
extendable-output functions (XOFs), they take an arbitrarily long message as
input and output a digest. As the name suggests, contrary to hash functions, the
output of a XOF can also be arbitrarily long. From FIPS 202:

    The suffixes “128” and “256” indicate the security strengths that these two
    functions can generally support, in contrast to the suffixes for the hash
    functions, which indicate the digest lengths.

:::{csv-table} Security levels of SHAKE functions, with SHA-256 for comparison
:header: Function name, Output size (bits), Collision resistance, Preimage resistance, 2nd preimage resistance
:stub-columns: 1

SHAKE128, Variable {math}`d`, "{math}`\min(d/2, 128)`", "{math}`\ge \min(d/2, 128)`", "{math}`\min(d/2, 128)`"
SHAKE256, Variable {math}`d`, "{math}`\min(d/2, 256)`", "{math}`\ge \min(d/2, 256)`", "{math}`\min(d/2, 256)`"
SHA-256, 256, 128, 256, 256
:::

While FIPS 202 does not approve any particular usage, [SP 800-185][SP-800-185]
specifies four SHA-3 derived functions, based on SHAKE:

- *cSHAKE*, a customizable variant of the SHAKE functions;
- *KMAC* (KECCAK Message Authentication Code), based on cSHAKE;
- *TupleHash*, a hash function based on cSHAKE to hash a tuple of input strings in
  an unambiguous way;
- *ParallelHash*, for efficiently hashing very long strings.

Another possible usage is as a key derivation function (KDF), in which case we
note that XOFs produce related outputs: producing a shorter digest of a
previously hashed message is simply the truncation of the first digest, e.g.
`XOF(K, 32) == XOF(K, 64)[:32]`.

## ANSSI rules and recommendations

> Source: [ANSSI - Guide des mécanismes cryptographiques](https://www.ssi.gouv.fr/uploads/2021/03/anssi-guide-mecanismes_crypto-2.04.pdf).

There are currently no rules or recommendations.

## ANSSI notes and recommendations

> Source: [ANSSI - Guide de sélection d'algorithmes cryptographiques](https://cyber.gouv.fr/sites/default/files/2021/03/anssi-guide-selection_crypto-1.0.pdf).

There are currently no notes or recommendations.

[FIPS202]: https://csrc.nist.gov/pubs/fips/202/final
[SPONGE]: https://en.wikipedia.org/wiki/Sponge_function
[SP-800-185]: https://csrc.nist.gov/pubs/sp/800/185/final
