# SPHINCS+

[SPHINCS+](https://sphincs.org/index.html) is a "stateless hash-based signature
scheme" based on the SPHINCS signature scheme {cite}`cryptoeprint:2014/795`.
Andreas Hülsing has a [blog post](https://huelsing.net/wordpress/?p=558) that
goes over the changes made to SPHINCS.

The latest version of the specification document at the time of writing can be
found [here](https://sphincs.org/data/sphincs+-r3.1-specification.pdf). Other
resources are listed in the [Resources](https://sphincs.org/resources.html)
section of the SPHINCS+ website.

SPHINCS+ is a *stateless* hash-based signature scheme, which means that is
doesn't require the user to save a state, unlike *stateful* schemes like XMSS
{cite}`cryptoeprint:2011/484`. The disadvantage of stateful schemes is that
reusing one-time key pairs may be catastrophic
{cite}`37619df38e9f48b0a8220e2afbd300be`.

The specification provides the following overview: "At a high level, SPHINCS+
works like SPHINCS. The basic idea is to authenticate a huge number of few-time
signature (FTS) key pairs using a so-called hypertree. FTS schemes are signature
schemes that allow a key pair to produce a small number of signatures, e.g., in
the order of ten for our parameter sets.  For each new message, a (pseudo)random
FTS key pair is chosen to sign the message. The signature consists then of the
FTS signature and the authentication information for that FTS key pair. The
authentication information is roughly a hypertree signature, i.e. a signature
using a certification tree of Merkle tree signatures.".

## Parameters

There are three different signature schemes, depending on the hash function used
to instantiate the SPHINCS+ construction:

- SPHINCS+-SHAKE256
- SPHINCS+-SHA-256
- SPHINCS+-Haraka

Haraka is a cryptographic hash function that aims to be efficient on short
inputs {cite}`cryptoeprint:2016/098`. While Haraka is not a hash function
approved by the NIST, the authors included this scheme to showcase the
performance of SPHINCS+ instantiated with a dedicated short-input hash function.

Each of these schemes was split into two variants during the second round of
submission: a simple and a robust variant. The robust variant is the one
introduced in the first round submission, while the simple variant "introduces
instantiations of the tweakable hash functions similar to those of the LMS
proposal \[{cite}`mcgrew_leighton-micali_2019`\] for stateful hash-based
signatures".

:::{csv-table} SPHINCS+ parameters
:header-rows: 1
:stub-columns: 1

Parameter, Description
{math}`n`, The security parameter in bytes.
{math}`w`, The Winternitz parameter.
{math}`h`, The height of the hypertree.
{math}`d`, The number of layers in the hypertree.
{math}`k`, The number of trees in FORS.
{math}`t`, The number of leaves of a FORS tree.
:::

:::{csv-table} SPHINCS+ parameter sets
:header: Parameter set, {math}`n`, {math}`h`, {math}`d`, {math}`\log(t)`, {math}`k`, {math}`w`, Bit security, NIST security level
:stub-columns: 1
:width: 100%

SPHINCS+-128s, 16, 63, 7, 12, 14, 16, 133, 1
SPHINCS+-128f, 16, 66, 22, 6, 33, 16, 128, 1
SPHINCS+-192s, 24, 63, 7, 14, 17, 16, 193, 3
SPHINCS+-192f, 24, 66, 22, 8, 33, 16, 194, 3
SPHINCS+-256s, 32, 64, 8, 14, 22, 16, 255, 5
SPHINCS+-256f, 32, 68, 17, 9, 35, 16, 255, 5
:::

:::{csv-table} SPHINCS+ parameter sizes
:header: Parameter set, Public key, Private key, Signature
:stub-columns: 1
:width: 100%

SPHINCS+-128s, 32, 64, 7856
SPHINCS+-128f, 32, 64, 17088
SPHINCS+-192s, 48, 96, 16224
SPHINCS+-192f, 48, 96, 35664
SPHINCS+-256s, 64, 128, 29792
SPHINCS+-256f, 64, 128, 49856
:::

## Implementations

The reference implementation can be found on GitHub:
[sphincs/sphincsplus](https://github.com/sphincs/sphincsplus). It has the three
main schemes, as well as optimized implementations:

- SPHINCS+-SHA256 with AVX2.
- SPHINCS+-SHAKE256 with AVX2.
- SPHINCS+-Haraka with AES-NI.

And include an aarch64 implementation of SPHINCS+-SHAKE256.

The [Software](https://sphincs.org/software.html) page of the website lists some third-party implementations such as:

- An integration in the [Botan C++](https://github.com/randombit/botan) library.
- [An implementation in Go](https://github.com/kasperdi/SPHINCSPLUS-golang).
- [One in Java](https://extgit.iaik.tugraz.at/krypto/javasphincsplus).
- An [hybrid variant](https://github.com/sfluhrer/hybrid-hash-based-signature), combining SPHINCS+ with the LMS scheme.
- An integration in [Bouncy Castle](https://github.com/bcgit).

Some integrations not listed there are:

- Open Quantum Safe's
[liboqs](https://openquantumsafe.org/liboqs/algorithms/sig/sphincs.html).
- [PQClean](https://github.com/PQClean/PQClean), which includes the same
variations as the reference repository (SHAKE256 with AVX2/in aarch64, SHA256
with AVX2, and Haraka with AES-NI).

## Benchmarks

While there are no benchmarks on the website, an extensive one is included in
[the specification](https://sphincs.org/data/sphincs+-r3.1-specification.pdf),
in Section 10, Table 4.

Benchmarks are also available in the
[SUPERCOP](https://bench.cr.yp.to/supercop.html) benchmarking framework.

Considering the number of variants, no benchmarks are proposed here.

## Attacks

Some attacks have been published:

- Breaking Category Five SPHINCS+ with SHA-256 {cite}`cryptoeprint:2022/1061`,
which gives "a complete forgery attack that reduces the concrete classical
security of these parameter sets by approximately 40 bits of security".
- Practical Fault Injection Attacks on SPHINCS {cite}`cryptoeprint:2018/674`, an
attack that  "allows the creation of a universal signature forgery that applies
to all current standardisation candidates (XMSS, LMS, SPHINCS+, and
Gravity-SPHINCS)".
- Grafting Trees: a Fault Attack against the SPHINCS framework
{cite}`cryptoeprint:2018/102`, in which the authors propose "the first fault
attack against the framework underlying SPHINCS, Gravity-SPHINCS and SPHINCS+".
- On Protecting SPHINCS+ Against Fault Attacks {cite}`cryptoeprint:2023/042`, in
which the author "adapts the original attack to SPHINCS+ reinforced with
randomized signing and extends the applicability of the attack to any
combination of faulty and valid signatures".

## Bibliography

:::{bibliography} sphincs.bib
:::
