# Tests

Directory for unit tests, run with `pytest`.

Tests are separated in sub-directories:

- `cli` is for tests interacting directly with the CLI using Typer's
`CliRunner`.  As the CLI commands interact with the primitives most of the tests
are here.
  - `test_method` and `test_wrap` are more generic tests for all primitives, as
  they don't depend heavily on the primitive selected.
- `primitives` contains tests for code that can't be tested through the CLI,
which is mainly input errors, e.g. using an unsupported mode of operation with
AES, as the CLI already has functions to avoid passing such inputs to the
primitives.
- `vectors` is for testing classes that deal with test vectors.
