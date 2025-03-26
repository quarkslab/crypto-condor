# HQC

{{ prolog }}

HQC (Hamming Quasi-Cyclic) is a key encapsulation mechanism (KEM) based on code
theory, and selected for standardization as a backup for ML-KEM ([NIST IR
8545](https://csrc.nist.gov/pubs/ir/8545/final)).

## Parameters

```{csv-table} Description of HQC parameters
:header-rows: 1
:stub-columns: 1

"Parameters", "Description"
"{math}`n_1`", "The length of the Reed-Solomon code."
"{math}`n_2`", "The length of the Reed-Muller code."
"{math}`n`", "The length of the ambient space (smallest primitive prime greater than {math}`n_1 n_2`)"
"{math}`w`", "The weight of the {math}`n`-dimensional vectors {math}`\mathbf{x}, \mathbf{y}`"
"{math}`w_\mathbf{r} = w_\mathbf{e}`", "The weight of {math}`\mathbf{r}_1, \mathbf{r}_2`"
```

```{csv-table} Size in bytes for HQC
:header-rows: 1
:stub-columns: 1

"Instance", "Public key", "Secret key", "Ciphertext", "Shared secret"
HQC-128, 2249, 56, 4497, 64
HQC-192, 4522, 64, 9042, 64
HQC-256, 7245, 72, 14485, 64
```

## Implementations

The reference implementation can be downloaded from the project's page:
[https://pqc-hqc.org/implementation.html](https://pqc-hqc.org/implementation.html).
There is also AVX2 and hardware optimized implementations.

HQC is integrated in Open Quantum Safe's
[liboqs](https://openquantumsafe.org/liboqs/algorithms/kem/hqc.html) and in
[PQClean](https://github.com/PQClean/PQClean).

## Attacks

The specification ([version 2025/02/19](https://pqc-hqc.org/doc/hqc-specification_2025-02-19.pdf)) has a section on known attacks. They include:

- Attacks against Syndrome Decoding: {cite}`prangeUseInformationSets1962`, {cite}`sternMethodFindingCodewords1989`, {cite}`torresAnalysisInformationSet2016`, {cite}`guoNewAlgorithmSolving2014`, {cite}`londahlSquaringAttacksMcEliece2016`, {cite}`sendrierDecodingOneOut2011`.
- Specific structural attacks: {cite}`beckerDecodingRandomBinary2012`, {cite}`mayComputingNearestNeighbors2015`, {cite}`mayDecodingRandomLinear2011`, {cite}`PDFMinimumDistance`.
- The choice of the parameters: {cite}`beckerDecodingRandomBinary2012`, {cite}`bernsteinAttackingDefendingMcEliece2008`, {cite}`bernsteinGroverVsMcEliece2010`, {cite}`canteautNewAlgorithmFinding1998`, {cite}`finiaszSecurityBoundsDesign2009`, {cite}`mayComputingNearestNeighbors2015a`, {cite}`mayDecodingRandomLinear2011a`, {cite}`sendrierDecodingOneOut2011a`, {cite}`torresAnalysisInformationSet2016a`.

More recent attacks include:

- OT-PCA: New Key-Recovery Plaintext-Checking Oracle Based Side-Channel Attacks on HQC with Offline Templates {cite}`dongOTPCANewKeyRecovery2024`.
- A New Key Recovery Side-Channel Attack on HQC with Chosen Ciphertext {cite}`goyNewKeyRecovery2022`
- A New Decryption Failure Attack Against HQC {cite}`guoNewDecryptionFailure2020`
- Cache-Timing Attack Against HQC {cite}`huangCacheTimingAttackHQC2023`

## Bibliography

```{bibliography} hqc.bib

```
