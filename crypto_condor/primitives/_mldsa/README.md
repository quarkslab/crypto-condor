# ML-DSA

crypto-condor uses the [reference
implementation](https://github.com/pq-crystals/dilithium) of
[Dilithium](https://pq-crystals.org/dilithium/index.shtml), specifically based on commit
[444cdcc84eb36b66fe27b3a2529ee48f6d8150c2](https://github.com/pq-crystals/dilithium/commit/444cdcc84eb36b66fe27b3a2529ee48f6d8150c2),
which implements the changes for ML-DSA from the Dilithium submission.

The changes done to integrate it into crypto-condor are described in the
`cc-mldsa.patch` file.

When this implementation is required, the source code is extracted from the zip
archive to a temporary directory and compiled. The resulting shared libraries,
one for each parameter set, are copied to the user's crypto-condor app data
directory, along with this notice. The libraries are loaded with `ctypes`.

The version used is the one found in the `ref` directory.

