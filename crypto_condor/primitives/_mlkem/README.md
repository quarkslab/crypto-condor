# ML-KEM

crypto-condor uses the [reference implementation](https://github.com/pq-crystals/kyber)
of [Kyber](https://pq-crystals.org/kyber/index.shtml), specifically based on commit
[10b478fc3cc4ff6215eb0b6a11bd758bf0929cbd](https://github.com/pq-crystals/kyber/commit/10b478fc3cc4ff6215eb0b6a11bd758bf0929cbd)
which implements the changes for ML-KEM from the Kyber submission.

The changes done to integrate it into crypto-condor are described in the
`cc-mlkem.patch` file.

When this implementation is required, the source code is extracted from the zip archive
to a temporary directory and compiled. The resulting shared libraries, one for each
ML-KEM parameter set, are copied to the user's crypto-condor app data directory, along
with this notice. The libraries are loaded with the `cffi` module.

The version used is the one found in the `ref` directory.
