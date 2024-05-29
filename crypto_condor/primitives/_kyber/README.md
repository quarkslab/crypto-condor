# Kyber

crypto-condor uses the [reference implementation](https://github.com/pq-crystals/kyber)
of [Kyber](https://pq-crystals.org/kyber/index.shtml), specifically based on
commit [b628ba78711bc28327dc7d2d5c074a00f061884e](https://github.com/pq-crystals/kyber/commit/b628ba78711bc28327dc7d2d5c074a00f061884e).

The changes done to integrate it into crypto-condor are described in the
`cc-kyber.patch` file.

When this implementation is required, the source code is extracted from the zip
archive to a temporary directory and compiled. The resulting shared libraries,
one for each Kyber parameter set, are copied to the user's crypto-condor app
data directory, along with this notice. The libraries are loaded with the `cffi`
module.

The version used is the one found in the `ref` directory.
