# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [CalVer](https://calver.org/).

## Unreleased

Nothing yet. :)

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

