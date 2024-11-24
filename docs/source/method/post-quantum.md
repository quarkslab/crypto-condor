# Post-quantum primitives

NIST announced the Post-Quantum Cryptography Standardization at PQCrypto 2016,
as an effort to standardize algorithms resistant to attacks that make use of
quantum-computers.

Out of 69 candidates that were considered for the first round of the
competition, 4 algorithms were selected at the end of the third round for
standardization.  There are 3 digital signature schemes, CRYSTALS-Dilithium,
Falcon, and SPHINCS+, and one {abbr}`KEM (Key Encapsulation Mechanism)`[^kem],
CRYSTALS-Kyber. NIST plans to recommend Kyber and Dilithium, while standardizing
Falcon for cases where Dilithium's signatures may be too large, and SPHINCS+ to
avoid relying only on lattice-based signature schemes.
This guide has entries for each:

:::{toctree}
:titlesonly:

Falcon
SPHINCS+
MLDSA
MLKEM
:::

[^kem]: <https://en.wikipedia.org/wiki/Key_encapsulation_mechanism>

Besides these algorithms, 4 other KEM candidates are going through a [fourth
round](https://csrc.nist.gov/projects/post-quantum-cryptography/round-4-submissions)
of analysis in order to standardize a KEM alternative to Kyber. These are BIKE,
Classic McEliece, HQC, and SIKE, though last year an attack on SIKE has been
published and the [team acknowledges SIKE should not be
used](https://csrc.nist.gov/csrc/media/Projects/post-quantum-cryptography/documents/round-4/submissions/sike-team-note-insecure.pdf).

And a new call for proposals for signature schemes with "short signatures and
fast verification" is ongoing. For a list of all signature scheme candidates,
see [Post-Quantum signatures zoo](https://pqshield.github.io/nist-sigs-zoo/).

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
  - [SPHINCS+](/method/SPHINCS+)
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

