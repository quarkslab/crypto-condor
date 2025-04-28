# Post-quantum primitives

NIST announced the Post-Quantum Cryptography Standardization at PQCrypto 2016,
as an effort to standardize algorithms resistant to attacks that make use of
quantum-computers.

Out of 69 candidates that were considered for the first round of the
competition, 4 algorithms were selected at [the end of the third
round](https://www.nist.gov/news-events/news/2022/07/nist-announces-first-four-quantum-resistant-cryptographic-algorithms)
for standardization.  There are 3 digital signature schemes, CRYSTALS-Dilithium,
Falcon, and SPHINCS+, and one {abbr}`KEM (Key Encapsulation Mechanism)`[^kem],
CRYSTALS-Kyber. NIST plans to recommend Kyber and Dilithium, while standardizing
Falcon for cases where Dilithium's signatures may be too large, and SPHINCS+ to
avoid relying only on lattice-based signature schemes.
This guide has entries for each:

:::{toctree}
:titlesonly:

Falcon
MLDSA
MLKEM
SLH-DSA <SLHDSA>
:::

[^kem]: <https://en.wikipedia.org/wiki/Key_encapsulation_mechanism>

Besides these algorithms, 4 other KEM candidates went through a [fourth
round](https://csrc.nist.gov/projects/post-quantum-cryptography/round-4-submissions)
of analysis in order to standardize a KEM alternative to Kyber. These are BIKE,
Classic McEliece, HQC, and SIKE, though in 2022 an attack on SIKE was published
and the [team acknowledges SIKE should not be
used](https://csrc.nist.gov/csrc/media/Projects/post-quantum-cryptography/documents/round-4/submissions/sike-team-note-insecure.pdf).

And a new call for proposals for signature schemes with "short signatures and
fast verification" is ongoing. For a list of all signature scheme candidates,
see [Post-Quantum signatures zoo](https://pqshield.github.io/nist-sigs-zoo/).

As of March 2025, there are [three finalized
standards](https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards):
ML-DSA (based on CRYSTALS-Dilithium), ML-KEM (based on CRYSTALS-Kyber), and
SLH-DSA (based on SPHINCS+). [NIST IR
8413](https://csrc.nist.gov/pubs/ir/8413/upd1/final) describes the selection
process and summarizes the algorithms considered during the third round,
including those selected for standardization or for the fourth round of
analysis. Falcon will be standardized as FN-DSA.

On March 2025, NIST [announced the selection of
HQC](https://csrc.nist.gov/News/2025/hqc-announced-as-a-4th-round-selection) for
standardization as the result of the [fourth
round](https://csrc.nist.gov/projects/post-quantum-cryptography/round-4-submissions).
[NIST IR 8545](https://csrc.nist.gov/pubs/ir/8545/final) "details the evaluation
criteria, algorithm designs, and reasoning behind the selection".

This guide has entries on the three signature schemes:

```{toctree}
:titlesonly:

Falcon
MLDSA
SLH-DSA <SLHDSA>
```

As well as for the two KEMs:

```{toctree}
:titlesonly:
HQC
MLKEM
```

## A quick comparison of signature schemes

While only one KEM algorithm has been selected at the end of Round 3, we have
three different signatures schemes to compare.

<!-- markdownlint-disable MD005 MD007 -->
:::{list-table}
:header-rows: 1
:stub-columns: 1

- -
  - [Dilithium](/method/MLDSA)
  - [Falcon](/method/Falcon)
  - [SPHINCS+](/method/SLHDSA)
- - Based on
  - (Module) lattices
  - NTRU lattices
  - Hash functions
- - Security based on
  - {abbr}`SVP (Shortest vector problem)`
  - {abbr}`SIS (Short integer solution)`, Floating-point arithmetic, and Gaussian sampling
  - Second-preimage resistance of the hash function
- - NIST security levels
  - 2, 3, and 5
  - 1 and 5
  - 1, 3, and 5
- - Pros
  -
    - Has the fastest signature generation without additional requirements.
    - It's easy to implement safely.
  -
    - Has the smallest {math}`|\text{pk}| + |\text{sig}|`.
    - Has a security proof for {abbr}`ROM (Random Oracle Model)` and {abbr}`QROM (Quantum Random Oracle Model)`.
    - Is modular: the class of lattices and the trapdoor sampler can be changed easily.
    - There are possible instantiations with message-recovery or key-recovery modes.
  -
    - Its security is based on the security of the underlying hash function.
    - Has different parameter sets with different tradeoffs.
    - Has the smallest public key.
- - Cons
  -
    - Has relatively large signatures and public keys.
  -
    - Delicate implementation: the key generation and fast Fourier sampler are non-trivial to understand.
    - Requires *fast constant-time double-precision floating-point arithmetic*, which currently requires workarounds.
  -
    - Has the largest signatures.
    - Has the slowest signature generation.
:::
<!-- markdownlint-enable MD005 MD007 -->

