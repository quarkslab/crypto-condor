# SLHDSA

{{ prolog }}

Stateless Hash-Based Digital Signature Algorithm (SLH-DSA) is a digital
signature scheme based on SPHINCS+ and standardized by NIST as [FIPS
205](https://csrc.nist.gov/pubs/fips/205/final). It is one of the three
signature schemes selected at the end of the third round of the NIST PQC
competition.

As the name implies, it is based on hash functions. More precisely, it relies on
the preimage resistance and related properties, not on the collision resistance.

```{note}
As with the other selected candidates, SLH-DSA introduces some changes to the
round 3 version of SPHINCS+, meaning that they are not compatible.
```

## Overview

SLH-DSA is based on SPHINCS+.
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

### Parameters

```{table} Description of the SLH-DSA Parameters
| Parameter | Description |
| --------- | ----------- |
| $n$       | The security parameter is the length in bytes of the messages that may be signed with WOTS+, as well as the length of the private key, public key and signature elements. |
| $h$       | The height of the XMSS hypertree. |
| $d$       | The number of layers of XMSS trees. |
| $h'$      | The height of a XMSS tree. |
| $a$       | The value such that $2^a$ is the number of byte strings in a single set of a FORS private key. |
| $k$       | The number of Merkle trees in FORS, conforming the private key. |
| $lg_w$    | The number of bits that are encoded with each WOTS+ hash chain used. |
```

> **Note** that the values are valid for both SHA-2 and SHAKE variants. For
> example, SLH-DSA-128s applies to both SLH-DSA-SHA2-128s and
> SLH-DSA-SHAKE-128s.

```{table} Parameter sets for SLH-DSA
| Parameter set | $n$ | $h$ | $d$ | $h'$ | $a$ | $k$ | $lg_w$ | $m$ | security category |
| ------------- | --- | --- | --- | ---- | --- | --- | ------ | --- | ----------------- |
| SLH-DSA-128s  | 16  | 63  | 7   | 9    | 12  | 14  | 4      | 30  | 1                 |
| SLH-DSA-128f  | 16  | 66  | 22  | 3    | 6   | 33  | 4      | 34  | 1                 |
| SLH-DSA-192s  | 24  | 63  | 7   | 9    | 14  | 17  | 4      | 39  | 3                 |
| SLH-DSA-192f  | 24  | 66  | 22  | 3    | 8   | 33  | 4      | 42  | 3                 |
| SLH-DSA-256s  | 32  | 64  | 8   | 8    | 14  | 22  | 4      | 47  | 5                 |
| SLH-DSA-256f  | 32  | 68  | 17  | 4    | 9   | 35  | 4      | 49  | 5                 |
```

```{table} Sizes of keys and signatures in SLH-DSA
| Parameter set | Public key | Private key | Signature |
| ------------- | ---------- | ----------- | --------- |
| SLH-DSA-128s  | 32         | 64          | 7856      |
| SLH-DSA-128f  | 32         | 64          | 17088     |
| SLH-DSA-192s  | 48         | 96          | 16224     |
| SLH-DSA-192f  | 48         | 96          | 35664     |
| SLH-DSA-256s  | 64         | 128         | 29792     |
| SLH-DSA-256f  | 64         | 128         | 49856     |
```

## Implementations

The reference implementation can be found on GitHub:
[sphincs/sphincsplus](https://github.com/sphincs/sphincsplus). Work for updating
the reference implementation to match the FIPS 205 standard can be found in the
[`consistent-basew`](https://github.com/sphincs/sphincsplus/tree/consistent-basew)
branch.

It has optimized implementations for the previous version, including an AVX2
version of SPHINCS+-SHA256 and SPHINCS+-SHAKE256.

The [Software](https://sphincs.org/software.html) page of the website lists some
third-party implementations such as:

- An integration in the [Botan C++](https://github.com/randombit/botan) library.
- An [hybrid variant](https://github.com/sfluhrer/hybrid-hash-based-signature), combining SPHINCS+ with the LMS scheme.
- An integration in [Bouncy Castle](https://github.com/bcgit).

Some integrations not listed there are:

- Open Quantum Safe's [liboqs](https://openquantumsafe.org/liboqs/algorithms/sig/sphincs.html).
- [PQClean](https://github.com/PQClean/PQClean), which includes the same variations as the reference repository (SHAKE256 with AVX2/in aarch64, SHA256 with AVX2, and Haraka with AES-NI).

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

```{bibliography} slhdsa.bib
```
