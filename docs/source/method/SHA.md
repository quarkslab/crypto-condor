# SHA

{{ prolog }}

SHA, or the Secure Hash Algorithms, are a family of cryptographic hash
functions, published and standardized by the NIST.

:::{list-table} Summary of ANSSI rules and recommendations
:header-rows: 1
:width: 100%

- - Rule/recommendation
  - SHA-1
  - SHA-2
  - SHA-3
- - Recommended/obsolete
  - {red}`Obsolete`
  - {green}`Recommended`
  - {green}`Recommended`
- - {ref}`RegleHash <sha-regle-hash>`
  - {red}`Not compliant`: (1) digest size is $160 < 256$ and (2) a known
  collision attack is estimated to require $2^{63} < 2^{160/2}$ operations.
  - {green}`Compliant`
  - {green}`Compliant`
- - {ref}`RecommandationHash <sha-rec-hash>`
  - {red}`Not compliant`
  - {green}`Compliant`
  - {green}`Compliant`

:::

## Overview

A quick rundown of SHA families:

- SHA-0, a hash function not included in this guide since it was withdrawn and
replaced by SHA-1.
- **SHA-1** is a 160-bit *hash function* based on the [Merkle-Damgård
construction][MD]. Attacks on a number of rounds have been found, and in 2017,
the [SHAttered attack](https://shattered.io/) was published.
- **SHA-2** is a *family of six hash functions* that are also based on the
[Merkle–Damgård construction][MD]. These functions are called SHA-*N*, where *N*
usually stands for the output size in bits.
- **SHA-3** is the latest addition, a *family of four hash functions* that are
*not* based on the Merkle–Damgård construction but on a [sponge
construction][SPONGE]. These functions are called SHA3-*N*, where *N* stands for
the output size in bits. While the names are similar, SHA-*N* only refers to
members of the SHA-2 family.
  - This new family is not meant to outright replace SHA-2, but to act as an
  alternative choice to SHA-2.
  - SHA-3 also introduced SHAKE128 and SHAKE256, two e**x**tendable-**o**utput
  **f**unctions (XOF).  The number in the name refers to their maximum security
  level in bits.

:::{csv-table} The SHA-2 family
:header: Hash function, Output size (bits), Collision resistance, Preimage resistance, 2nd preimage resistance, Comment
:stub-columns: 1

SHA-224, 224, 112, 224, 224, Truncated version of SHA-256 with different initial value
SHA-256, 256, 128, 256, 256,
SHA-348, 384, 192, 384, 384, Truncated version of SHA-512 with different initial value
SHA-512, 512, 256, 512, 512
SHA-512/224, 224, 112, 224, 224, Truncated version of SHA-512
SHA-512/256, 256, 128, 256, 256, Truncated version of SHA-512
:::

:::{csv-table} The SHA-3 family
:header: Function name, Output size (bits), Collision resistance, Preimage resistance, 2nd preimage resistance
:stub-columns: 1

SHA3-224, 224, 112, 224, 224
SHA3-256, 256, 128, 256, 256
SHA3-384, 384, 192, 384, 384
SHA3-512, 512, 256, 512, 512
SHAKE128, Variable {math}`d`, "{math}`\min(d/2, 128)`", "{math}`\ge \min(d/2, 128)`", "{math}`\min(d/2, 128)`"
SHAKE256, Variable {math}`d`, "{math}`\min(d/2, 256)`", "{math}`\ge \min(d/2, 256)`", "{math}`\min(d/2, 256)`"
:::

## ANSSI rules and recommendations

> Source: [ANSSI - Guide des mécanismes cryptographiques](https://www.ssi.gouv.fr/uploads/2021/03/anssi-guide-mecanismes_crypto-2.04.pdf)

:::{admonition} RegleHash
:class: attention
:name: sha-regle-hash

1. The minimum size of digests produced by a hash function is 256 bits.
2. The best known attack for finding collisions must require at least $2^{h/2}$
   hashing operations, where $h$ is the size in bits of the digests.
:::

:::{admonition} RecommandationHash
:name: sha-rec-hash

1. The use of hash functions for which "partial attacks" are known is not
   recommended.
:::

## Hash length extension attack

Length extension attacks are a type of attack that given a hash of an unknown
message `M` allow to construct the hash of `(M || pad || M')`, where `pad` is
the implicit padding added by the hash function and `M'` is an arbitrary
message.

Hash functions based on the [Merkle–Damgård construction][MD] are susceptible to
this attack: **SHA-256 and SHA-512 are vulnerable**. (Older algorithms such as
SHA-1 and MD5 are vulnerable too).

Truncated versions of SHA-2 algorithms should not be affected as this attack
relies on the fact that the output of non-truncated versions is their internal
state, so by truncating the output the attacker can no longer continue from
where the previous execution ended. This includes SHA-512/224 and SHA-512/256.
It also includes SHA-384 and SHA-224, but due to the smaller truncation the
protection against these attacks is less than that of SHA-512/224 and
SHA-512/256.

Members of the SHA-3 family were designed with these attacks in mind, so their
design based on the [sponge construction][SPONGE] means that **SHA-3 hash
functions are not affected** by this attack.

This type of attack has been exploited previously: see [Flickr's API Signature
Forgery
Vulnerability](https://dl.packetstormsecurity.net/0909-advisories/flickr_api_signature_forgery.pdf).

To illustrate this type of attack, an example using MD5 can be found in the
following notebook:

:::{toctree}
sha/hash_length_extension
:::

<!-- References -->
[MD]: https://en.wikipedia.org/wiki/Merkle%E2%80%93Damg%C3%A5rd_construction
[SPONGE]: https://en.wikipedia.org/wiki/Sponge_function
