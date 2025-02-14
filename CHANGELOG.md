# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [CalVer](https://calver.org/).

## Unreleased

### Added

- *(docs)* Add the `wrapper-api` section ([2e23991](https://github.com/quarkslab/crypto-condor/commit/2e239911864aa8a3d766d27eaa51430c3e66b846)).
  - This will group the naming convention and protocols that wrappers use.
- *(docs)* Add the SHAKE method guide ([2e23991](https://github.com/quarkslab/crypto-condor/commit/2e239911864aa8a3d766d27eaa51430c3e66b846)).
  - Separates it from the SHA guide, without modifying the latter.
- *(SHAKE)* Add the `test_digest` function to replace `test` ([2e23991](https://github.com/quarkslab/crypto-condor/commit/2e239911864aa8a3d766d27eaa51430c3e66b846)).
  - We want to provide one function per operation to test, with the function
    name explicitly indicating the operation.
- *(SHAKE)* Add the `test_output_digest` function for output mode support ([2e23991](https://github.com/quarkslab/crypto-condor/commit/2e239911864aa8a3d766d27eaa51430c3e66b846)).

### Changed

- *(SHAKE)* Update the test vectors ([2e23991](https://github.com/quarkslab/crypto-condor/commit/2e239911864aa8a3d766d27eaa51430c3e66b846)).
  - Internally, they were moved to the `_shake` module, while creating new
    protobufs with the harmonised format. Additionally, they combine the
    different CAVP files into one, simplifying the results displayed (one per
    (algorithm, orientation) combination tested).
- *(SHAKE)* Update the Python wrapper to behave similar to the harness ([2e23991](https://github.com/quarkslab/crypto-condor/commit/2e239911864aa8a3d766d27eaa51430c3e66b846)).

### Deprecated

- *(SHAKE)* The `test` function is deprecated in favour of `test_digest` ([2e23991](https://github.com/quarkslab/crypto-condor/commit/2e239911864aa8a3d766d27eaa51430c3e66b846)).
  - `test` will be removed in a later version.

### Fixed

- *(docs)* Fix SHA example in CLI quickstart ([baf1ea8](https://github.com/quarkslab/crypto-condor/commit/baf1ea808f7068028e0d4b124417e77992cb69d6)).

## 2025.02.07

### Fixed

- *(AES)* Fix results returned by AES.test_lib ([28525c1](https://github.com/quarkslab/crypto-condor/commit/28525c1deb63bbc3b03b2c1e835af9bb39a29d47)).
  - `AES.test_lib` returned a list of Results instead of ResultsDict.
- *(RSA)* Fix typo in RSA._test_verify_pss_wycheproof ([58aa61f](https://github.com/quarkslab/crypto-condor/commit/58aa61f9e938e5c4338b734d74b97e4791cf7224)).
  - Some results were being overwritten due to a typo in the key for the
    ResultsDict returned by `RSASSA.test_verify_pss`.
- *(tests)* Fix unused harness test ([f253c79](https://github.com/quarkslab/crypto-condor/commit/f253c7910042161f09fbb28104fe1156528011bf)).
  - Harnesses were not being tested due to a misnamed file.

### Changed

- *(common)* Enforce key uniqueness in ResultsDict ([a6d2a06](https://github.com/quarkslab/crypto-condor/commit/a6d2a060c5fd7b64ae800d5ead55f28b6ced8d0d), [#8](https://github.com/quarkslab/crypto-condor/issues/8)).
  - Add checks to ResultsDict to raise ValueError when setting a duplicate key.

## 2025.01.31

### Changed

- *(chore)* Update dependencies ([b7ec5d0](https://github.com/quarkslab/crypto-condor/commit/b7ec5d0431961b4e9a4e4744032c06a2d3b6c58a)).
  - Bumped dependencies with Poetry, manually tested with tox to verify it
    doesn't break compatibility with Python 3.10 and 3.11.

### Fixed

- *(package)* Fix missing test vectors in wheel ([a4187dc](https://github.com/quarkslab/crypto-condor/commit/a4187dc425602b3ef3a2447a14ff3449f2f5b301), [#13](https://github.com/quarkslab/crypto-condor/issues/13)).
  - All protobuf test vectors were missing from the wheel of version 2025.01.19
    due to a change in how Poetry interprets its configuration. They are
    explicitly included in both the wheel and sdist now.

## 2025.01.19

### Added

- **Breaking**: add ML-DSA and ML-KEM (3855df8e).
    - Dilithium and Kyber are replaced by ML-DSA and ML-KEM respectively. This
      includes updating the reference implementation and the test vectors.
    - The wrappers usage is simplified, adopting a similar approach to the
      harness mode: the wrapper defines functions recognized by crypto-condor
      such as `CC_MLKEM_512_encaps()`, removing the need for passing parameters
      through the CLI, and thus allowing to test more than one set of parameters
      at a time. This change will be propagated to other primitives eventually.
    - Additionally, the language of the wrapper is inferred from the file
      extension.
    - Now both primitives support the `output` mode (encapsulation for ML-KEM
      and signing for ML-DSA).
    - The protocols have been updated, particularly for ML-DSA, taking the
      signature and message separately instead of concatenated (the previous
      *signed message*).
    - Method guides have *not* been updated yet.
- utils: add protobuf and parsing script templates (8df71abc, 33676c1b, fb43ae12)
    - The protobuf template defines the common set of fields test vectors should have.
    - The parsing script template serves as a base for writing the script, along
      with the function that generates a JSON file that defines which vectors
      are available depending on the parameter selected.
    - The CONTRIBUTING page has been updated to use ML-KEM as an example of
      these new templates.
- common: `new_from_test` method for `TestInfo`, which takes a test vector
  directly instead of unpacking its values. Relies on the new test vectors
  template (e256bf23).

### Fixed

- Typo in method guide template, which prevented the docs from building (dae27832).

## 2024.09.24

### Fixed

- CLI: display help when running `testu01` command without arguments (6920307f).
- README: bump minimum Python version to 3.10 (abf1f822).
  - The minimum supported version was already 3.10, this only updates the
    README.
- SHA: ensure key uniqueness for test results (e5bce86d).
  - Test results of different algorithms (but not two implementations of the
    same algorithm) can be safely combined.
- docs: links to ANSSI documents (1d9b0a73).

### Added

- Test harness mode (eb8b73e4).
  - New feature to test primitives from a shared library. Currently supports
    AES, SHA, SHAKE, Kyber, and Dilithium. For more information,
    [read the docs](https://quarkslab.github.io/crypto-condor/latest/harness-api/index.html)

### Changed

- Updated `cryptography` to 43.0.0 (c75811db).
  - This is **potentially breaking** as 43.0.0 drops supports for OpenSSL less
    than 1.1.1e and LibreSSL less than 3.8.
- Packaging of the C implementations of AES, Kyber, and Dilithium (dbe30575).
  - Instead of compiling an executable, these implementations are compiled as
    shared libraries, used with CFFI. It should improve the performance without
    changing the user experience.

### Removed

- AES: support for the `segment_size` option is removed (dbe30575).
  - Instead, it is directly inferred from the mode of operation used.

## 2024.08.23

### Fixed

- ECDH: Wrong test attribute in Wycheproof test (#11, 83204324).
- common: Missing `importlib.metadata` import (a1b55d6f).
- common: Small improvements to result display (d4cf7ea8).

### Added

- cli: --debug option to save debug data (#10, 8e4b295f).
- docs: Documentation for `common.Console` (#9, 0d907ca1).

## 2024.08.19

### Fixed

- common: Passing `None` to `Console.process_results` does not work as
  documented (#7, 3b6fef74).

## 2024.08.03

### Fixed

- ECDSA: `test_sign` fails to verify signature when using the `pre_hashed`
  option (#4, 6871c6e5, b1c1ddc5).
- ECDSA: Verify test crashes when saving the results (#5, 1d7019df).

## 2024.07.03

- **Breaking**: changed the usage of the AES and SHA wrappers.
  - The C wrapper templates no longer come with a Makefile and are no longer
    compiled by crypto-condor. Instead, the user must compile the wrapper
    themselves.
  - The names of the AES and SHA wrapper files are no longer hard-coded: now
    both the Python API and the CLI expect a filename pointing to a Python
    wrapper or a compiled C wrapper.
- Add support for Python **3.10**.
- Fix long tracebacks on uncaught exceptions. This was because local variables
  were included, such as the entire list of current test vectors. Local
  variables are now omitted from tracebacks by default, but can be added back by
  increasing the verbosity.

## 2024.06.12

- Changed the requirements for TestU01: no longer depends on a TeX Live
  installation, just a C compiler that defaults to `/usr/bin/cc`.
- Fixed a bug with SHA wrappers that caused swapping until the program crashes.
- Add support for XDG_DATA_HOME and %LOCALAPPDATA% to choose where to store
  application data.

## 2024.06.10

Small update to fix some issues.

- Fixed missing folders in the package, preventing Kyber and Dilithium from
  being installed.
- Fixed an error in the docs for the CLI quickstart, `get-wrapper`/`test
  wrapper` example.
- Fixed a bug that resulted in an exception when saving debug data to a file.
- Added some debugging information when installing TestU01 by not capturing the
  subprocess output under some conditions such as using -vv (debug-level
  logging).

## 2024.06.04

The first public release of crypto-condor!

