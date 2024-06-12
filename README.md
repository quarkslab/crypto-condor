# crypto-condor

<img align="right" src="crypto-condor.png" width="250" alt="The logo of crypto-condor, depicting a condor holding a key.">

crypto-condor is a tool for compliance testing of cryptographic primitives, in
the form of a Python library and CLI. It is complemented by an extensive
documentation, featuring guides on the primitives supported.

**Q: What is a cryptographic primitive?**

**A**: A low-level cryptographic algorithm, generally used to build a protocol.
For example, AES is an encryption primitive that is used in the TLS protocol,
which is the protocol your browser used to securely get this page.

**Q: What is compliance testing?**

**A**: Algorithms are described in specifications, such as FIPS publications or
RFCs. When implementing these algorithms, we want to ensure that they comply
with the specification, i.e. the implementation behaves as the algorithm
described.

**Q: How to test for compliance then?**

**A**: We can use *test vectors*, which are sets of inputs and their
corresponding outputs. For example, encrypting with AES is a deterministic
operation: for a given key and message, AES will always return the same
ciphertext. So we can choose some input values, run the algorithm, and record
the value returned. All implementations of AES are then expected to return the
*same* ciphertext for this given key and message. If it does not, then it is not
compliant.

**Q: And so, what does crypto-condor do?**

**A**: crypto-condor provides both a nice Python API and a wrapper system to
test implementations with sets of test vectors that come from sources such as
the [NIST
CAVP](https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program).

The Python API exposes test functions that take an implementation as input, in
the form of a Python function or class, passes the inputs defined by the test
vectors to that implementation, and checks if the outputs are those defined by
the vectors.

The wrappers are small programs that already define the function prototype. The
user calls the implementation to test inside this function, and crypto-condor
runs it with the test vectors as with the Python API.

And it comes with a documentation, wrapper examples, and guides on supported
primitives.

## Requirements

crypto-condor requires **Python 3.11+**. For information, it is developed using
Python 3.12.2 on Fedora 39.

The implementations of **AES, Kyber, Dilithium, and TestU01** are written in C
and are compiled directly on the user's machine. As such, they require a C
compiler and GNU Make. These primitives are only compiled when required, and not
when installing the package:

- AES: when testing the output of an implementation using classic modes of
operation (not CCM or GCM).
- Kyber: when testing the output of an implementation **or** when using test
vectors on the `encapsulate` function.
- Dilithium: when testing the output of an implementation.
- TestU01: when used to test a file.

## Installation

It is available on PyPI:

```bash
python -m pip install crypto-condor
```

An up-to-date list of the requirements can be found in the
`[tool.poetry.dependencies]` section of the
[pyproject.toml](https://github.com/quarkslab/crypto-condor/blob/main/pyproject.toml)
file.

## Usage

> The documentation is available at
> <https://quarkslab.github.io/crypto-condor/latest/index.html>.

Once installed, the CLI is available as `crypto-condor-cli`. It is structured in
commands, similar to Git. Run it without arguments or with `--help` to display
the help message detailing the available subcommands. You can check [the
documentation](https://quarkslab.github.io/crypto-condor/latest/index.html) for
a quick rundown of all the commands.

As for the Python library, it is available as `crypto_condor` (note the
underscore). Each primitive has its own module under `primitives`, e.g.
`crypto_condor.primitives.AES`. It contains the functions used to test
implementations.

## Development

See
[CONTRIBUTING](https://github.com/quarkslab/crypto-condor/blob/main/CONTRIBUTING.md).

## Changelog and versioning

A [changelog](https://github.com/quarkslab/crypto-condor/blob/main/CHANGELOG.md)
is available. This projects adheres to [CalVer](https://calver.org/). The format
used is YYYY.MM.DD\[.MICRO\]\[-MODIFIER\]:

- YYYY: full year (2023).
- 0M: zero-padded month (01, 02, ..., 12).
- 0D: zero-padded day (01, 02, ..., 31).
- MICRO: an increasing counter, used for patches published in the same day.
- MODIFIER: usually `rc<n>` to indicate a release candidate.

## Authors

- Julio Loayza Meneses, Quarkslab.
- Angèle Bossuat, Quarkslab.
- Dahmun Goudarzi, Quarkslab.

Logo idea by Robin David, drawing by Irene Loayza.

