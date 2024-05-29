# CRYSTALS-Dilithium

[Dilithium](https://pq-crystals.org/dilithium/index.shtml) is "a digital
signature scheme that is strongly secure under chosen message attacks based on
the hardness of lattice problems over module lattices"
{cite}`schwabe_dilithium_nodate`.

The latest version of the specification at the time of writing can be found
[here](https://pq-crystals.org/dilithium/data/dilithium-specification-round3-20210208.pdf).

> A high-level overview of the scheme is available in [this
> presentation](https://csrc.nist.gov/CSRC/media/Presentations/Crystals-Dilithium/images-media/CRYSTALS-Dilithium-April2018.pdf).
> NIST submission packages and the different versions of the paper are available
> in the [Resources](https://pq-crystals.org/dilithium/resources.shtml) page.

Dilithium is based on the "Fiat-Shamir with Aborts" approach described in
{cite}`hutchison_fiat-shamir_2009`, {cite}`hutchison_lattice_2012`, and
resembles the schemes {cite}`hutchison_practical_2012` and
{cite}`hutchison_improved_2014`.

Unlike the schemes presented in {cite}`canetti_lattice_2013` and
{cite}`sarkar_efficient_2014` that sample randomness from a discrete Gaussian
distribution, Dilithium uses uniform sampling. This was proposed in
{cite}`hutchison_fiat-shamir_2009` and {cite}`hutchison_practical_2012`, and has
the advantage of avoiding the problem of safely implementing Gaussian sampling,
which is hard to protect against side-channel attacks such as
{cite}`gierlichs_flush_2016`, {cite}`espitau_side-channel_2017`, and
{cite}`pessl_bliss-b_2017`.

While Dilithium is a random scheme, it offers a deterministic variant which the
authors recommend by the default as long as side-channel attacks that exploit
determinism cannot be mounted. For examples, see {cite}`smart_breaking_2018` and
{cite}`poddebniak_attacking_2018`.

The operations used for signing and verification are mostly expansion of an XOF,
in this case SHAKE128 and SHAKE256. The other set of heavily used operations are
multiplications in {math}`R_q`, which is why the scheme uses the same ring for
all parameter sets. As with Kyber, polynomial mulitiplication is implemented
with the [Number Theoretic
Transform](https://en.wikipedia.org/wiki/Discrete_Fourier_transform_over_a_ring#Number-theoretic_transform).

The authors offer two recommendations:

> - Use Dilithium in a so-called hybrid mode in combination with an established
>   "pre-quantum" signature scheme.
> - We recommend using the Dilithium3 parameter set, which—according to a very
>   conservative analysis—achieves more than 128 bits of security against all known
>   classical and quantum attacks.

This scheme uses the ring {math}`R_q = \mathbb{Z}_q[X] / (X^n + 1)`, with
{math}`q = 2^{23} - 2^{13} + 1` and {math}`n = 256`.

## Parameters

:::{csv-table} Dilithium parameter sets
:header: Parameter, NIST sec 2, NIST sec 3, NIST sec 5, Description
:stub-columns: 1
:align: center

{math}`q`, 8380417, 8380417, 8380417, Modulus
{math}`d`, 13, 13, 13, Dropped bits from {math}`\boldsymbol{t}`
{math}`\tau`, 39, 49, 60, Number of {math}`\pm 1` in {math}`c`
Challenge entropy, 192, 225, 257, {math}`\log \binom{256}{\tau} + \tau`
{math}`\gamma_1`, {math}`2^{17}`, {math}`2^{19}`, {math}`2^{19}`, {math}`\boldsymbol{y}` coefficient range
{math}`\gamma_2`, {math}`(q-1) / 88`, {math}`(q-1)/32`, {math}`(q-1)/32`, low-order rounding range
"{math}`(k,l)`", "{math}`(4,4)`", "{math}`(6,5)`", "{math}`(8,7)`", Dimensions of {math}`\boldsymbol{A}`
{math}`\eta`, 2, 4, 2, Secret key range
{math}`\beta`, 78, 196, 120, {math}`\tau \cdot \eta`
{math}`\omega`, 80, 55, 75, Maximum number of ones in the hint {math}`\boldsymbol{h}`
Repetitions, 4.25, 5.1, 3.85
:::

:::{csv-table} Dilithium sizes in bytes
:header-rows: 1
:stub-columns: 1

Parameters set, Public key, Private key, Signature, NIST security level
Dilithium2, 1312, 2528, 2420, 2
Dilithium3, 1952, 4000, 3293, 3
Dilithium5, 2592, 4864, 4595, 5
:::

## Implementations

- The reference and the AVX2 optimized implementations can be found in the
[pq-crystals/dilithium](https://github.com/pq-crystals/dilithium) repository.
- It is integrated into Open Quantum Safe's
[liboqs](https://openquantumsafe.org/liboqs/algorithms/sig/dilithium.html).
- It is integrated into [PQclean](https://github.com/PQClean/PQClean), including
an aarch64 implementation.

Other third-party implementations are referenced in Dilithium's
[Software](https://pq-crystals.org/dilithium/software.shtml) page, such as:

- An integration in the [Botan C++](https://github.com/randombit/botan) library.
- An [implementation in Rust](https://github.com/Argyle-Software/dilithium).
- An integration in [Bouncy Castle](https://downloads.bouncycastle.org/betas/).
- An [implementation in Java](https://github.com/mthiim/dilithium-java).

## Benchmarks

Benchmarks performed on an Intel i7-8565u using the [provided
programs](https://github.com/pq-crystals/dilithium#benchmarking-programs).

There are also benchmarks provided by the authors in
[Dilithium's homepage](https://pq-crystals.org/dilithium/index.shtml)
as well as
[benchmarks from the SUPERCOP benchmarking framework](http://bench.cr.yp.to/results-sign.html#amd64-kizomba).

:::{csv-table} Dilithium cycles
:header-rows: 1
:stub-columns: 1
:width: 100%

Parameter set, Key generation, Sign, Verify
Dilithium2, 182956, 753125, 199536
Dilithium3, 316955, 1324089, 304934
Dilithium5, 498482, 1579503, 526596
Dilithium2 AVX2, 55235, 141680, 54872
Dilithium3 AVX2, 85148, 223664, 88795
Dilithium5 AVX2, 136783, 268426, 132707
:::

:::{csv-table} Dilithium AES cycles
:header-rows: 1
:stub-columns: 1
:width: 100%

Parameter set, Key generation, Sign, Verify
Dilithium2aes, 371173, 1074952, 359543
Dilithium3aes, 675773, 1862761, 624963
Dilithium5aes, 1247287, 2510715, 1111386
Dilithium2aes AVX2, 34764, 122613, 38536
Dilithium3aes AVX2, 57075, 162428, 58841
Dilithium5aes AVX2, 70887, 180428, 76336
:::

## Attacks

[The
paper](https://pq-crystals.org/dilithium/data/dilithium-specification-round3-20210208.pdf)
has a section called "Concrete security", which goes over the problems that the
scheme is based on and their known attacks.

Side-channel attacks against Dilithium have been published:

- Differential Fault Attacks on Deterministic Lattice Signatures {cite}`groot_bruinderink_differential_2018`.
- Exploiting Intermediate Value Leakage in Dilithium: A Template-Based Approach {cite}`cryptoeprint:2023/050`.
- An Efficient Non-Profiled Side-Channel Attack on the CRYSTALS-Dilithium Post-Quantum Signature {cite}`chen_efficient_2021`.
- Practical Public Template Attacks on CRYSTALS-Dilithium With Randomness Leakages {cite}`9924203`.

Other attacks:

- Signature Correction Attack on Dilithium Signature Scheme, {cite}`islam2022signature`.

## Bibliography

:::{bibliography} dilithium.bib
:::
