# AES

{{ prolog }}

The Advanced Encryption Standard is a symmetric block cipher, based on the
Rijndael cipher. It was standardised by NIST in 2001 on [FIPS 197][FIPS197].

:::{list-table} Summary of ANSSI rules and recommendations
:header-rows: 1

- - Rule or recommendation
  - Comments
- - ANSSI: recommended or obsolete?
  - {green}`Recommended`
- - {ref}`RègleBlocSym <aes-regle-bloc-sym>`
  - Follows rule 2, {green}`OK` for long-term use (beyond 2026).
- - {ref}`RecommendationBlocSym <aes-rec-bloc-sym>`
  - {green}`Recommended`, block size if 128 bits.
- - {ref}`RègleCléSym <aes-regle-cle-sym>`
  - Follows rule 2, {green}`OK` for long-term use (beyond 2026).
- - {ref}`RecommendationCléSym <aes-rec-cle-sym>`
  - {green}`Recommended`, minimum key length if 128 bits.
- - {ref}`RègleBlocSym <aes-regle-bloc-sym>`
  -
    1. {green}`OK` for use up to 2025.
    2. {green}`OK` for long-term use (beyond 2026).
    3. With a block size {math}`n=128` a single key can be used to encrypt {math}`2^{n/2 - 5} = 2^{59}` blocks.
:::

## Overview

There are three variants standardised by [FIPS 197][FIPS197]: AES-128, AES-192,
AES-256. The differences between variants are the key size (128, 192, and 256
bits respectively) and the number of rounds.

All three variants have a block size of 128 bits, meaning that they can only
encrypt or decrypt 128 bits of data. To address larger data sizes, they are used
with a *mode of operation*, which chains calls to the block cipher to process
arbitrary amounts of data[^arbitrary].

[^arbitrary]: There are limitations linked to the key size and IV to maintain
    the security guarantees of the system.

### Modes of operation

There are two types of modes of operation: confidentiality-only and
authenticated modes. The latter ensures both the confidentiality of the message
as well as its integrity, so using these modes should be preferred when
possible. Note that confidentiality-only modes are used by authenticated modes,
and that the following recommendations apply when using these modes to construct
authenticated ones.

#### Confidentiality-only modes

These modes of operation require an IV, which must either be:

- a value generated with a cryptographically secure pseudo-random number
  generator;
- a value that must be used only once (a *nonce*).

The different modes of operation are:

:::{list-table} Classic modes of operation
:header-rows: 1
:stub-columns: 1

- - Mode
  - Status
  - Comments
- - CTR
  - {green}`Recommended`
  - Stream mode: never re-use the same (key, IV) pair as this allows an attacker to recover the XOR of both plaintexts.
- - OFB
  - {green}`Recommended`
  - Stream mode: never re-use the same (key, IV) pair as this allows an attacker to recover the XOR of both plaintexts.
- - CBC
  - {green}`Recommended`
  -
    - Requires padding, as it treats messages whose length is a multiple of the block size. Since it requires padding, implementations must ensure the decryption process prevents padding oracle attacks.
    - TLS 1.3 has eliminated support for CBC.
- - CBC-CS
  - {green}`Recommended`
  -
- - CFB
  - {green}`Recommended`
  - Requires padding, as it treats messages whose length is a multiple of the block size. Since it requires padding, implementations must ensure the decryption process prevents padding oracle attacks.

:::

#### Authenticated modes

The modes GCM, CCM, and EAX are recommended when used with a recommended
primitive such as AES.

:::{list-table} AEAD modes of operation
:header-rows: 1

- - Mode
  - Status
  - Comments
- - CCM
  - {green}`Recommended`
  -
- - GCM
  - {green}`Recommended`
  -
    - Never re-use an IV. GCM, like other counter modes, is a stream cipher, so using the same (key, IV) pair leaks information on the plaintext.
    - GCM is only recommended if the IV is 96 bits long and is constructed with the deterministic construction.
    - Given that the block size of AES is 128 bits, a single key can be used to encrypt up to {math}`2^{39} - 256` bits or {math}`2^{32} - 2` blocks.
    - The MAC must be at least 128 bits, meaning that it can't be truncated.
- - EAX
  - {green}`Recommended`
  -

:::

### Constructions

Constructions refer to ways of combining a (block) cipher with a Message
Authentication Code (MAC) to ensure both the confidentiality and the
authenticity of the message.

:::{list-table} Constructions
:header-rows: 1

- - Construction
  - Status
  - Comments
- - Encrypt-then-MAC
  - {green}`Recommended`
  -
    - The keys used for encryption and the computation of the MAC must be independent.
    - The integrity of the IV or nonce used by the encryption must be ensured.
- - Mac-then-Encrypt
  - {red}`Deprecated`
  -
    - The keys used for encryption and the computation of the MAC must be independent.
    - The integrity of the IV or nonce used by the encryption must be ensured.
- - Encrypt-and-MAC
  - {red}`Deprecated`
  -
    - The keys used for encryption and the computation of the MAC must be independent.
    - The integrity of the IV or nonce used by the encryption must be ensured.

:::

## ANSSI rules and recommendations

> Source: [ANSSI - Guide des mécanismes cryptographiques](https://www.ssi.gouv.fr/uploads/2021/03/anssi-guide-mecanismes_crypto-2.04.pdf)

### Symmetric keys

:::{admonition} RègleCléSym
:class: attention
:name: aes-regle-cle-sym

1. For symmetric keys used up to 2025, the minimum length is 112 bits.
2. For symmetric keys used from 2026 onwards, the minimum length is 128 bits.
:::

:::{admonition} RecommandationCléSym
:name: aes-rec-cle-sym

The minimum recommended length for symmetric keys is 128 bits.
:::

### Block ciphers

:::{admonition} RègleBlocSym
:class: attention
:name: aes-regle-bloc-sym

1. For use up to 2025, the minimum block size is 64 bits.
2. For use from 2026 onwards, the minimum block size is 128 bits.
3. The maximum number of blocks encrypted with a single key is {math}`2^{n/2 - 5}`,
   where $n$ is the block size in bits.
:::

:::{admonition} RecommendationBlocSym
:name: aes-rec-bloc-sym

The recommended block size for block ciphers is 128 bits.
:::

:::{admonition} RègleAlgoBloc
:class: attention
:name: aes-regle-algo-bloc

1. For an algorithm used up to the end of 2025, no attack requiring less than
   {math}`2^{100}` operations must be known.
2. For an algorithm used in 2026 and beyond, no attack requiring less than
   {math}`2^{125}` operations must be known.
:::

:::{admonition} RecommendationAlgoBlog
:name: aes-rec-algo-bloc

1. It is recommended to use block cipher algorithms that are well-tested and
   scrutinized by academia.
:::

### Modes of operation

:::{admonition} RègleModeChiff
:class: attention
:name: aes-regle-mode-chiff

1. There must be no attack of complexity less than {math}`2^{n/2}` calls of the
   primitive, where {math}`n` is the bit size of the block.
:::

:::{admonition} RecommandationModeChiff
:name: aes-rec-mode-chiff

1. The use of a non-deterministic encryption mode of operation is recommended.
2. An encryption mode of operation will be preferably used with an integrity mechanism. This
   mechanism can be independent from the encryption mode.
3. Preferably use modes of operation that have a security proof.
:::

### Stream ciphers

:::{admonition} RègleChiffFlot
:class: attention
:name: aes-regle-chiff-flot

1. For a stream cipher algorithm used up to the end of 2025, there must not be a
   known attack requiring less than {math}`2^{100}` operations.
2. For a stream cipher algorithm used in 2026 and beyond, there must not be a
   known attack requiring less than {math}`2^{125}` operations.
:::

:::{admonition} RecommendationChiffFlot
:name: aes-rec-chiff-flot

1. It is recommended to use block cipher primitives instead of stream cipher ones. If the properties
   of a stream cipher are required, it is possible to use a mode of operation of a block cipher that
   is recommended and emulates a stream cipher.
2. If a stream cipher is used, it is recommended that the algorithm used has been scrutinized by
   academia.
:::

<!-- References -->
[FIPS197]: https://csrc.nist.gov/pubs/fips/197/final
