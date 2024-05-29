# Falcon

[Falcon](https://falcon-sign.info/) (Fast-Fourier Lattice-based Compact
Signatures over NTRU) is a hash-and-sign lattice-based signature scheme. It is
based on the GPV framework instantiated over NTRU lattices and a new technique
called "fast Fourier sampling".

Falcon was designed with the idea of compactness: the objective was to minimize
{math}`|pk| + |sig|`, the bit-size of the public key and the signature.  So
lattice-based signatures were chosen using the hash-and-sign GPV framework
{cite}`gentry_trapdoors_2008`.  This framework was chosen due to the proofs that
it is secure in the classical Random Oracle Model under the SIS assumption
{cite}`gentry_trapdoors_2008` (adapted for NTRU lattices) and in the Quantum
Random Oracle Model {cite}`cryptoeprint:2010/428`.

This framework requires two ingredients: a class of lattices and a trapdoor
sampler.  The class of lattices chosen for Falcon are the NTRU lattices
introduced in {cite}`goos_ntru_1998`.  They have the advantages of providing a
compact instantiation of GPV {cite}`sarkar_efficient_2014`, as their structure
reduces the size of the public key, of speeding up many operations, and
{cite}`cryptoeprint:2013/004` showed that GPV with NTRU can be used in a
provably secure way.

The second ingredient is the trapdoor sampler, which takes as input a matrix
{math}`\boldsymbol{A}`, a trapdoor {math}`T`, and a target
{math}`\boldsymbol{c}` and returns a short vector {math}`\boldsymbol{s}` such
that {math}`\boldsymbol{s}^t \boldsymbol{A} = c \mod q`.  The trapdoor sampler
used in Falcon is the one introduced in {cite}`10.1145/2930889.2930923`, "fast
Fourier nearest plane"[^fft] which can be randomized to provide a trapdoor
sampler that combines the security of the most secure sampler (Klein's algorithm
{cite}`10.5555/338219.338661`) with the efficiency the fastest generic trapdoor
sampler (Peikert's {cite}`cryptoeprint:2010/088`) while being compatible with
NTRU lattices.

[^fft]: The name comes from the fact that "it proceeds in a recursive way which
is very similar to the fast Fourier transform".

An important parameter is the standard deviation {math}`\sigma`. If it's too low
it may leak the secret basis, and if it's too high the vectors returned are not
optimally short.  The fast Fourier sampler shares similarities with Klein's,
including the optimal value {math}`\sigma`.  Following
{cite}`cryptoeprint:2017/480`, {math}`\sigma = \eta_{\epsilon}(\mathbb{Z}_{2n})
\cdot \| {B}_{GS} \|`.

## Parameters

:::{csv-table} Falcon parameter sets
:header-rows: 1
:stub-columns: 1
:align: center

Parameter set, NIST level, Ring degree {math}`n`, Modulus {math}`q`, Standard deviation {math}`\sigma`, {math}`\sigma_{\min}`, {math}`\sigma_{\max}`, Max. signature square norm {math}`\lfloor \beta^2 \rfloor`
Falcon-512, 1, 512, 12289, 165.736617183, 1.277833697, 1.8205, 34 034 726
Falcon-1024, 5, 1024, 12289, 168.388571447, 1.298280334, 1.8205, 70 265 242
:::

:::{csv-table} Falcon bytelength sizes
:header-rows: 1
:stub-columns: 1

Parameter set, Public key, Signature
Falcon-512, 897, 666
Falcon-1024, 1793, 1280
:::

## Implementations

- The reference implementation can be found in the Resources section of the
[homepage](https://falcon-sign.info/). There is a [browsable
version](https://falcon-sign.info/impl/falcon.h.html) and a [source code
archive](https://falcon-sign.info/Falcon-impl-20211101.zip).
- There is also a [Python implementation](https://github.com/tprest/falcon.py)
done by Thomas Prest, one of the authors.
- An implementation can be found in the [submission
package](https://falcon-sign.info/falcon-round3.zip), though it differs from the
current version.
- Falcon is integrated in [PQclean](https://github.com/PQClean/PQClean). It
includes an AVX2-optimized version.
- An ARM Cortex-M4 version is available in the [pqm4
library](https://github.com/mupq/pqm4).

:::{note}
It seems that the reference implementation does not follow NIST's [API
notes](https://csrc.nist.gov/CSRC/media/Projects/Post-Quantum-Cryptography/documents/example-files/api-notes.pdf).
:::

## Benchmarks

The following benchmarks were obtained with the `speed` program provided in the reference implementation, running on an Intel i7-8565u.

The time are all in microseconds, except for the key generation which is in milliseconds.

CT indicates that the operations use a constant-time version of `hash-to-point`.

:::{csv-table} Benchmark
:header-rows: 1
:stub-columns: 1
:align: center

Parameter set, Key generation, Sign, Sign CT, Sign with expanded key, Sign with expanded key CT, Verify, Verify CT
512, 7.92, 357.83, 374.78, 239.96, 252.36, 32.84, 56.11
1024, 25.43, 700.00, 721.45, 456.85, 534.86, 83.26, 117.59
:::

A benchmark is also available on [Falcon's homepage](https://falcon-sign.info/).

## Attacks

The paper includes a section called Security in which known attacks are listed.
Among them we find:

- Key recovery using lattice reduction with, for example, DBKZ {cite}`fischlin_practical_2016`.
- An overview of how to forge signature using Kannan's embedding with a sieve
algorithm is given. This example is used to calculate the estimated bit security
of the two levels based on {cite}`becker_new_2016`,
{cite}`b0cf4f60d1cf454ca5c294f2b4608119`, and {cite}`cryptoeprint:2015/1092`.

There are a number of side-channel attacks that have been published:

- Improved Power Analysis Attacks on Falcon, {cite}`cryptoeprint:2023/224`.
- FALCON Down: Breaking FALCON Post-Quantum Signature Scheme through Side-Channel Attacks, {cite}`9586131`.
  - There is [a presentation](https://csrc.nist.gov/csrc/media/Presentations/2022/falcon-down/images-media/session2-aysu-falcon-down-pqc2022.pdf) which gives an overview of how the attack works.
- A Differential Fault Attack against Deterministic Falcon Signatures, {cite}`cryptoeprint:2023/422`.

## Bibliography

:::{bibliography} falcon.bib
:::
