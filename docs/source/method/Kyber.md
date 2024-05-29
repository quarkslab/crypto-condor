# CRYSTALS-Kyber

[Kyber](https://pq-crystals.org/kyber/index.shtml) is "an IND-CCA2-secure key
encapsulation mechanism (KEM), whose security is based on the hardness of
solving the learning-with-errors (LWE) problem over module lattices".

In the following guide:

- {math}`R` denotes the ring {math}`\mathbb{Z}[X]/(X^n + 1)`.
- {math}`R_q` denotes the ring {math}`\mathbb{Z}_q[X]/(X^n + 1)`.
- {math}`n = 2^{n'-1}` such that {math}`X^n + 1` is the {math}`2^{n'}`-th cyclotomic polynomial.
- {math}`\mathcal{B}^K` (resp. {math}`\mathcal{B}^*`) is the set of bytes arrays
  of length {math}`k` (resp. of arbitrary length).

## Parameters

:::{csv-table} Kyber parameter description
:header-rows: 1
:stub-columns: 1

"Parameters", "Description"
"{math}`n`", "{math}`n = 2^{n' - 1}` such that {math}`X^n + 1` is the {math}`2^{n'}`-th cyclotomic polynomial."
"{math}`k`", "The lattice dimension is set to a multiple of {math}`n`, with {math}`k` being the multiplier. Kyber uses this parametrize the security/efficiency of the algorithm."
"{math}`q`", "A small prime satisfying {math}`n | (q-1)` while retaining CCA security. Using a small prime allows the use of fast multiplication based on {abbr}`NTT (number-theoretic transform)`."
"{math}`\eta_1`, {math}`\eta_2`", "Kyber uses a centered binomial distribution noted {math}`B_{\eta}`, with {math}`\eta = 2` or {math}`\eta = 3`, for sampling noise. {math}`\eta_1` defines the noise used in Kyber.CPAPKE.KeyGen and some of the noise in Kyber.CPAPKE.Enc, while {math}`\eta_2` defines the noise of Kyber.CPAPKE.Enc only."
"{math}`d_u`, {math}`d_v`", "Control the ciphertext compression."
:::

:::{csv-table} Kyber parameter values
:header-rows: 1
:stub-columns: 1
:width: 100%
:align: center

"Parameter set", {math}`n`, {math}`k`, {math}`q`, {math}`\eta_1`, {math}`\eta_2`, {math}`d_u`, {math}`d_v`, "NIST security level", "Equivalent AES security"
Kyber512, 256, 2, 3329, 3, 2, 10, 4, 1, AES-128
Kyber768, 256, 3, 3329, 2, 2, 10, 4, 3, AES-192
Kyber512, 256, 4, 3329, 2, 2, 11, 5, 5, AES-256
:::

:::{csv-table} Kyber key sizes (in bytes)
:header-rows: 1
:stub-columns: 1

"Parameter set", "Private key", "Public Key", "Ciphertext"
Kyber512, 1632, 800, 768
Kyber768, 2400, 1184, 1088
Kyber1024, 3168, 1568, 1568
:::

There is a variant of Kyber that uses the existing hardware support for
symmetric primitives.  Called Kyber-90s, it uses AES-256-CTR and SHA2.

The authors offer two recommendations:

> - Using Kyber in a *hybrid-mode*, combined with an established primitive such as
>   elliptic curve Diffie-Hellman.
> - Using the Kyber768 parameter set, which is estimated to achieve more than 128
>   bits of security.

## Implementations

The reference implementation can be found on GitHub:
[pq-crystals/kyber](https://github.com/pq-crystals/kyber). It includes an
optimized version with AVX2.

The [repository and the NIST submission
packages](https://pq-crystals.org/kyber/resources.shtml) include an AVX2
optimized implementation.

Kyber is integrated in Open Quantum Safe's
[liboqs](https://openquantumsafe.org/liboqs/algorithms/kem/kyber) and
[PQClean](https://github.com/PQClean/PQClean). The latter includes an aarch64
version.

Other third-party implementations are referenced in the
[Software](https://pq-crystals.org/kyber/software.shtml) page, such as:

- An integration in Cloudflare's [CIRCL](https://github.com/cloudflare/circl)
{cite}`sullivan_securing_2020`.
- An integration in Amazon's [AWS Key Management
Service](https://aws.amazon.com/kms/) {cite}`weibel_round_2020`.
- An integration in the [Botan C++](https://github.com/randombit/botan) library.
- An integration in [Bouncy Castle](https://downloads.bouncycastle.org/betas/).
- And implementations in a variety of programming languages such as
[Rust](https://github.com/Argyle-Software/kyber),
[Python](https://github.com/asdfjkl/pyky),
[Java](https://github.com/fisherstevenk/kyberJCE), and
[Go](https://git.schwanenlied.me/yawning/kyber).

## Benchmarks

Benchmarks performed on an Intel i7-8565u using the [provided
programs](https://github.com/pq-crystals/kyber#benchmarking-programs).

There are also benchmarks provided by the authors in [Kyber's
homepage](https://pq-crystals.org/kyber/index.shtml) as well as [benchmarks from
the SUPERCOP benchmarking
framework](http://bench.cr.yp.to/results-kem.html#amd64-kizomba).

:::{csv-table} Kyber cycles
:header-rows: 1
:stub-columns: 1
:width: 100%

Parameter set, Key generation, Encapsulation, Decapsulation
Kyber512, 78335, 90264, 106145
Kyber768, 124656, 142119, 208495
Kyber1024, 185777, 212082, 265636
Kyber512 AVX2, 12755, 22709, 22268
Kyber768 AVX2, 27143, 37498, 28226
Kyber1024 AVX2, 43098, 48344, 40643
:::

:::{csv-table} Kyber-90s cycles
:header-rows: 1
:stub-columns: 1
:width: 100%

Parameter set, Key generation, Encapsulation, Decapsulation
Kyber512-90s,  108869, 134826, 143744
Kyber768-90s,  196670, 221077, 242194
Kyber1024-90s, 305843, 392176, 491882
Kyber512 AVX2, 13736,  20315,  12789
Kyber768 AVX2, 16085,  22532,  14556
Kyber1024 AVX2, 20939, 26990,  20392
:::

## Attacks

[The paper](https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf) has a section called "Analysis with respect to known attacks.

More recently, there have been a number of side-channels attacks:

- A Side-Channel Attack on a Hardware Implementation of CRYSTALS-Kyber,
{cite}`ji_side-channel_2023`.
- A Side-Channel Secret Key Recovery Attack on CRYSTALS-Kyber Using k Chosen
Ciphertexts, {cite}`el_hajji_side-channel_2023`, {cite}`yang_chosen_2023`.
- Secret Key Recovery Attacks on Masked and Shuffled Implementations of
CRYSTALS-Kyber and Saber, {cite}`cryptoeprint:2022/1692`.
- Chosen-Ciphertext Clustering Attack on CRYSTALS-Kyber Using the Side-Channel
Leakage of Barrett Reduction, {cite}`sim_chosen-ciphertext_2022`.

## Bibliography

:::{bibliography} kyber.bib
:::
