# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [CalVer](https://calver.org/).

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

