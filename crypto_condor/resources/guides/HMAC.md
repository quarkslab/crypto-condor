# HMAC

{{ prolog }}

HMAC, or key-Hashed MAC or Hash-based MAC, is a Message Authentication Code
(MAC).

:::{list-table} Summary of ANSSI rules and recommendations
:header-rows: 1
:width: 100%

- - Rule/recommendation
  - SHA-1
  - SHA-2
  - SHA-3
- - Recommended/obsolete
  - - {red}`Obsolescent` with $K > 100$ bits (see {ref}`Note 4.3.c <note-4-3-c>`).
    - **{red}`Obsolete`** otherwise.
  - - {green}`Recommended` with $K > 128$ bits.
    - {red}`Obsolescent` with $128 > K \ge 100$ bits.
  - - {green}`Recommended` with $K > 128$ bits.
    - {red}`Obsolescent` with $128 > K \ge 100$ bits.
- - {ref}`RegleIntegSym <regle-integ-sym>`
  - {red}`Not compliant`: (1) usage of SHA-1 is {red}`tolerated` (see {ref}`Note
  4.3.c <note-4-3-c>`).
  - {green}`Compliant`
  - {green}`Compliant`
:::

## Overview

MACs are computed from a message $m$ and a secret key $K$, and are used to
verify the integrity and authenticity of the message sent. MAC functions can
also be used in a key derivation function such as PBKDF2.

As the name implies, HMAC is based on hash functions, specifically
*cryptographic* hash functions. While the original paper
[[BCK96](https://cseweb.ucsd.edu/~mihir/papers/kmd5.pdf)] specifies its usage
with MD5 and SHA-1, nowadays it is recommended to use it with functions from the
SHA-2 and SHA-3 families (see for example {rfc}`6151` and [the SHA method
guide](/method/SHA)).

HMAC is described in {rfc}`2104`, {rfc}`6234`, and was standardized by NIST in
[FIPS 198-1](https://csrc.nist.gov/pubs/fips/198-1/final). It is constructed as
follows:

$$
HMAC(K, m) = H\Bigl(\bigl(K' \oplus opad\bigr) || H\bigl((K' \oplus ipad) ||
m\bigr)\Bigr)
$$

Where:

- $K$ is the secret key.
- $m$ is the message.
- $H$ is the cryptographic hash function.
- $K'$ is a key derived from $K$. The size of $K'$ must be the same size as the
hash function's block.
  - If the size of $K$ is equal to the size of the block of the hash function, $K' = K$.
  - If it is shorter, it is padded to the right with zeroes.
  - If it is longer, it is hashed with $H$ and then padded to the right with zeroes.
- $ipad$ is the inner padding. It is the same size as the hash function's block
  and consists of `0x36` bytes.
- $opad$ is the outer padding. It is the same size as the hash function's block
  and consists of `0x5c` bytes.

HMAC was designed to prevent [hash length extension
attacks](/method/SHA.md#hash-length-extension-attack), to which simpler
constructions based on SHA-1 and SHA-2, such as $H(k || m)$, are vulnerable to.

## ANSSI rules and recommendations

> Source: [Guide des mécanismes cryptographiques](https://cyber.gouv.fr/sites/default/files/2021/03/anssi-guide-mecanismes_crypto-2.04.pdf)

:::{admonition} RègleIntegSym
:class: attention
:name: regle-integ-sym

1. The most common symmetrical methods for integrity are based on block-cipher
   or hashing mechanisms. These primitives must be compliant.
2. There should not exist an attack on the integrity mechanism requiring less
   than $2^{n/2}$ calls to the underlying primitive, where $n$ is the size of
   the output of the primitive.
:::

:::{admonition} RecommandationIntegSym
:name: recommandation-integ-sym

1. Prefer mechanisms that have a security proof.
:::

## ANSSI notes and recommendations

> Source: [Guide de sélection d'algorithmes cryptographiques](https://cyber.gouv.fr/sites/default/files/2021/03/anssi-guide-selection_crypto-1.0.pdf)

For bandwidth reasons, MACs can be truncated. The size of the output must be
sufficiently large to prevent an adversary from randomly generating a valid MAC.

:::{admonition} R7: MAC truncation

In general, it is not recommended to truncate the output of a function that
generates MACs to less than 96 bits.
:::

In constrained devices, such as smart cards, it is possible to come across MACs
truncated to 64 bits.

:::{admonition} Note 4.3.a: Truncating MACs to 64 bits
:class: attention

It is *tolerated* to truncate a MAC down to 64 bits **if** the maximum number of
verifications performed with a single key is $2^{20}$.
:::

:::{admonition} Note 4.3.c: HMAC-SHA-1
:name: note-4-3-c

The security of HMAC does *not* rely on the collision resistance of the
underlying hash function. While the usage of SHA-1 is forbidden in general,
which is why it was not included in this guide as an obsolescent
mechanism[^include], the usage of HMAC-SHA-1 is **tolerated**.
:::

[^include]: The "Guide de sélection d'algorithmes cryptographiques" only
    includes cryptographic algorithms that are either recommended, or considered
obsolescent, meaning that ANSSI recognizes their widespread use and considers
its security sufficient for short-term usage. If an algorithm is *not* included
in the guide, it is considered **obsolete** and should not be used at all.
