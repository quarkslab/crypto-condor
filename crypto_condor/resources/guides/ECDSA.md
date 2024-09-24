# ECDSA

{{ prolog }}

The Elliptic Curve Digital Signature Algorithm is a digital signature standard
described in [FIPS 186][FIPS186].  It is a variant of the Digital
Signature Algorithm (DSA) based on elliptic-curve cryptography.

Deterministic ECDSA is a variant of this algorithm that does not require the
generation of a secret number, thus may be useful for devices without access to
a good random number generator such as embedded devices.  The verification of
signatures produced with this variant remains the same.

According to [FIPS 186][FIPS186], "ECDSA and deterministic ECDSA require that the
private/public key pairs used for digital signature generation and verification
be generated with respect to a particular set of domain parameters.  These
domain parameters may be common to a group of users and may be public".  They
are described in [SP 800-186][SP.800-186] and summarized below.

:::{list-table} ECDSA domain parameters
:header-rows: 1

- - Parameter
  - Description
- - The elliptic curve field
  - Defined by its size {math}`q = p^k`, where {math}`p` is prime. ECDSA is
  defined for the finite field GF({math}`p`) and the finite field
  GC({math}`2^m`).
- - The equation of the curve
  - Defined by two field elements called {math}`a` and {math}`b`.
- - {math}`G`
  - A base point of (large) prime order on the curve.
- - {math}`n`
  - The order of the point {math}`G`.
- - {math}`h`
  - The cofactor of {math}`G` (equal to the order of the curve divided by {math}`n`).
- - Type
  - The elliptic curve model used.

:::

:::{list-table} ECDSA signature parameters
:header-rows: 1

- - Parameter
  - Description
- - {math}`d`
  - The private key, a integer randomly generated in the interval {math}`[1, n-1]`.
- - {math}`Q`
  - The public key, equal to {math}`d \times G`.
- - {math}`r` and {math}`s`
  - An ECDSA signature is represented by two integers {math}`0 < r < n` and {math}`0 < s < n`.

:::

Here is a list of elliptic curves approved for use in ECDSA by either the ANSSI or the NIST.

:::{csv-table} Elliptic curves for ECDSA
:header: Curve, ANSSI, NIST
:stub-columns: 1

P-224, {red}`No`,    {green}`Yes`
P-256, {green}`Yes`, {green}`Yes`
P-384, {green}`Yes`, {green}`Yes`
P-521, {green}`Yes`, {green}`Yes`
B-283, {green}`Yes`, {red}`No`
B-409, {green}`Yes`, {red}`No`
B-571, {green}`Yes`, {red}`No`
FRP256v1, {green}`Yes`, {red}`No`

:::

Some key points to keep in mind regarding this algorithm:

- As in public key cryptography in general, the private key **must** remain
secret.
  - NIST indicates that "Care must be taken to protect implementations against
  attacks, such as side-channel attacks or fault attacks" ([FIPS 186][FIPS186]).
- "(Deterministic) ECDSA keys **shall** only be used for the generation and
verification of (deterministic) ECDSA digital signatures" ([FIPS 186][FIPS186]).
- It is important to verify the correctness of the group arithmetic
computations:
  - Check that the points used and the results belong to the curve.
  - Particularly for deterministic signature schemes or embedded devices.
  - Measures to prevent small subgroup attacks [TODO: expand].
- The comparable security strength[^security-strength] is
{math}`\text{len}(n)/2` where {math}`\text{len}(n)` is the bit length of
{math}`n`.
- The security strength of the hash function must be at least the same as the
security strength associated with the bit length of {math}`n`.
- The same domain parameters may be used for more than one purpose, however
using different domain parameters reduces the risk of using key pairs for more
than one purpose.
- ECDSA requires the generation of a random per-message secret number, while
deterministic ECDSA derives it from the key and the message. This number
**must** remain secret and its generation must be unbiased. Section 7.3 of
[ANSSI's Guide de sélection d'algorithmes cryptographiques][ANSSI-PA-079]
describes its recommended methods of generating random numbers.
- An approved hash function or XOF (SHAKE128 or SHAKE256) and approved random
bit generator shall be used when generating signatures.

:::{list-table} Hash function and XOFs for ECDSA
:header-rows: 1
:stub-columns: 1
:width: 100%

- - Family
  - Parameter size (in bits)
  - Source
- - SHA-2
  - 224, 256, 384, 512, 256 (SHA-512/224), 256 (SHA-512/256)
  - [FIPS 180-4][FIPS180]
- - SHA-3
  - 256, 384, 512
  - [FIPS 202][FIPS202]
- - XOF
  - SHAKE128, SHAKE256
  - [FIPS 202][FIPS202]

:::

## ANSSI rules and recommendations

> Source: [Guide des mécanismes cryptographiques](https://cyber.gouv.fr/sites/default/files/2021/03/anssi-guide-mecanismes_crypto-2.04.pdf)

### Discrete logarithm for elliptic curves defined over GF({math}`p`)

:::{admonition} RègleECp
:class: attention
:name: ecdsa-regle-ecp

- Use subgroups whose order is a multiple of a prime number that is at least 250
  bits long.
    1. When using curves whose security relies of a mathematical problem that is
       easier than the generic elliptic curve discrete logarithm problem for
       elliptic curves defined over {math}`GF(p)`, the problem must verify the
       corresponding rules.
:::

:::{admonition} RecommandationECp
:name: ecdsa-rec-ecp

1. It is recommended to use subgroups whose order is prime (instead of being a
   multiple of a prime number).
:::

- Compliant curves
  - FRP256v1 ([JORF0241-16.10.2011][JORF0241-16.10.2011]), P-256, P-384, P-521
  ([FIPS 186][FIPS186]), brainpoolP256r1, brainpoolP384r1, or
  brainpoolP512r1 ([RFC 5639][RFC5639]).

### Discrete logarithm for elliptic curves defined over GF({math}`2^n`)

:::{admonition} RègleEc2
:class: attention
:name: ecdsa-regle-ec2

1. The order of the subgroup must be a multiple of a prime number that is at
   least 250 bits long.
2. The parameter {math}`n` must be a prime number.
3. When using curves whose security relies of a mathematical problem that is
   easier than the generic elliptic curve discrete logarithm problem for
   elliptic curves defined over {math}`GF(2^n)`, the problem must verify the
   corresponding rules.
:::

:::{admonition} RecommandationEC2
:name: ecdsa-rec-ec2

1. It is recommended to use subgroups whose order is prime (instead of being the
   multiple of a prime).
:::

- Compliant curves
  - B-283, B-409, and B-571 ([FIPS 186][FIPS186]).

### Hash functions

:::{admonition} RègleHash
:class: attention
:name: ecdsa-regle-hash

1. The minimal size of the resulting digest is 256 bits.
2. The best known attack allowing to find collisions requires at least
   {math}`2^{h/2}` digests.
:::

:::{admonition} RecommandationHash
:name: ecdsa-rec-hash

1. The use of hash function for whom "partial attacks" are known is discouraged.
:::

- Compliant hash functions
  - SHA-256 ([FIPS 180-4][FIPS180]) is compliant.
- Non-compliant hash functions
  - SHA-1 is not compliant:
    - It produces a 160-bit output, so it doesn't follow RègleHash-1.
    - It is vulnerable to a collision attack with complexity
    {math}`2^{63} < 2^{80}`, so it doesn't follow RègleHash-2.

### Asymmetric signature

:::{admonition} RecommandationSignAsym
:name: ecdsa-ref-sign-asym

1. It is recommended to use an asymmetric signature mechanism that has a
   security proof.
:::

- Compliant signature mechanisms
  - ECDSA is compliant when using curves FRP256v1, P-256, P-384, P-521, B-283,
  B-409, and B-571.

### Asymmetric keypairs

:::{admonition} RègleGestAsym
:class: attention
:name: regle-gest-asym

1. The same asymmetric key pair may not be used for more than one purpose.
2. Hierarchically important keys, such as root keys, must be generated and used
   by compliant mechanisms.
:::

[^security-strength]: "A number associated with the amount of work (i.e., the
number of operations) that is required to break a cryptographic algorithm or
system" ([FIPS 186-5][FIPS186]).

<!-- References -->
[ANSSI-PA-079]: https://www.ssi.gouv.fr/uploads/2021/03/anssi-guide-selection_crypto-1.0.pdf
[FIPS180]: https://csrc.nist.gov/publications/detail/fips/180/4/final
[FIPS186]: https://csrc.nist.gov/publications/detail/fips/186/5/final
[FIPS202]: https://csrc.nist.gov/publications/detail/fips/202/final
[JORF0241-16.10.2011]: https://www.legifrance.gouv.fr/jorf/id/JORFTEXT000024668816
[RFC5639]: https://datatracker.ietf.org/doc/html/rfc5639
[SP.800-186]: https://csrc.nist.gov/publications/detail/sp/800-186/final
