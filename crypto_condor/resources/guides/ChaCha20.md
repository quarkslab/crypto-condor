# ChaCha20

{{ prolog }}

[ChaCha20][CHACHA] is a stream cipher built on a symmetric block cipher close to
[Salsa20][SALSA]. It is often paired with [Poly1305][POLY], a universal hash
family, used as a one-time MAC (Message Authentication Code). A slightly
different version is described in {rfc}`7539`.

:::{list-table} Summary of ANSSI rules and recommendations
:header-rows: 1

- - Rule or recommendation
  - Comments
- - ANSSI: recommended or obsolete?
  - {green}`Recommended`
- - {ref}`RègleCléSym <chacha20-regle-cle-sym>`
  - Follows rule 2, {green}`OK` for long-term use (beyond 2026).
- - {ref}`RecommendationCléSym <chacha20-rec-cle-sym>`
  - {green}`Recommended`, minimum key length is 128 bits.
- - {ref}`RègleChiffFlot <chacha20-regle-chiff-flot>`
  - Follows rule 2, {green}`OK` for long-term use (beyond 2026), no known attack requiring less than {math}`2^{125}` operations.
- - {ref}`RecommendationChiffFlot <chacha20-rec-chiff-flot>`
  -
    1. {green}`OK`, it uses a block cipher primitive with counter mode of operation.
    2. {green}`OK`, it does not use a stream cipher primitive.
- - {ref}`RègleIntegSym <chacha20-regle-integ-sym>`
  -
    1. {green}`OK`, Poly1305 is based on a block primitive which complies with the standard.
    2. {green}`OK`, no attacks using fewer than {math}`2^{n/2}` calls to the underlying primitive, where $n$ is the output size of that primitive.
- - {ref}`RecommandationIntegSym <chacha20-rec-integ-sym>`
  - {green}`Recommended`, proof from Bernstein that Poly1305-AES or Poly1305-AnotherFunction has a security close to the underlying primitive.
:::

## Overview

:::{list-table} ChaCha20 parameters
:header-rows: 1

- - Parameter
  - Value
  - Comment
- - Block size
  - 64 bytes / 512 bits
  -
- - Key length
  - 256 bits
  - Treated as eight 32-bit little-endian integers.
- - Nonce length
  - 96 bits
  - Treated as three 32-bit little-endian integers.
- - Block count length
  - 32 bits
  - Treated as a 32-bit little-endian integers.

:::

Some key points to keep in mind regarding this algorithm:

- The nonce should not be reused: encrypting two different plaintexts with the
same key and nonce results in the XOR of the plaintexts being equal to the XOR
of the resulting ciphertexts, which is a strong confidentiality breach. The
integrity is also affected by a nonce reuse.
- The block count usually starts at 0 for ChaCha20 but in ChaCha20-Poly1305 the
first block is used for `Poly1305_Key_Gen` so at the first encrypted block the
block counter is at 1.

## ANSSI rules and recommendations

> Source: [Guide des mécanismes cryptographiques](https://cyber.gouv.fr/sites/default/files/2021/03/anssi-guide-mecanismes_crypto-2.04.pdf)

### Symmetric keys

:::{admonition} RègleCléSym
:class: attention
:name: chacha20-regle-cle-sym

1. For symmetric keys used up to 2025, the minimum length is 112 bits.
2. For symmetric keys used from 2026 onwards, the minimum length is 128 bits.
:::

:::{admonition} RecommendationCléSym
:name: chacha20-rec-cle-sym

The minimum recommended length for symmetric keys is 128 bits.
:::

### Stream ciphers

:::{admonition} RègleChiffFlot
:class: attention
:name: chacha20-regle-chiff-flot

1. For a stream cipher algorithm used up to the end of 2025, there must not be a
   known attack requiring less than {math}`2^{100}` operations.
2. For a stream cipher algorithm used in 2026 and beyond, there must not be a
   known attack requiring less than {math}`2^{125}` operations.
:::

:::{admonition} RecommendationChiffFlot
:name: chacha20-rec-chiff-flot

1. It is recommended to use block cipher primitives instead of stream cipher ones. If the properties
   of a stream cipher are required, it is possible to use a mode of operation of a block cipher that
   is recommended and emulates a stream cipher.
2. If a stream cipher is used, it is recommended that the algorithm used has been scrutinized by academia.
:::

### Symmetric encryption

:::{admonition} RègleIntegSym
:class: attention
:name: chacha20-regle-integ-sym

1. The most traditional symmetric integrity methods rely on block encryption or hashing mechanisms. Such primitives must comply with the reference framework.
2. There should be no attack on the integrity mechanism using fewer than {math}`2^{n/2}` calls to the underlying primitive, where {math}`n` is the output size of that primitive.
:::

:::{admonition} RecommandationIntegSym
:name: chacha20-rec-integ-sym

1. It is preferable to use mechanisms that have a security proof.
:::

<!-- References -->
[CHACHA]: https://cr.yp.to/chacha/chacha-20080128.pdf
[SALSA]: https://cr.yp.to/snuffle/design.pdf
[POLY]: https://cr.yp.to/mac/poly1305-20050329.pdf
