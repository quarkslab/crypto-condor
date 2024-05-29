# Dilithium

crypto-condor uses the [reference
implementation](https://github.com/pq-crystals/dilithium) of
[Dilithium](https://pq-crystals.org/dilithium/index.shtml), version
[3.1](https://github.com/pq-crystals/dilithium/releases/tag/v3.1).

The changes done to integrate it into crypto-condor are described in the
`dilithium.patch` file.

When this implementation is required, the source code is extracted from the zip
archive to a temporary directory and compiled. The resulting shared libraries,
one for each parameter set, are copied to the user's crypto-condor app data
directory, along with this notice. The libraries are loaded with `ctypes`.

The version used is the one found in the `ref` directory, without randomized
signing. The Dilithium-AES variant is not used.

