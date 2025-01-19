# Contributing to crypto-condor

Be it issues, pull requests, or suggestions, contributions are welcome!

## Requirements for development

The external dependencies are (not including Python packages):

- [poetry](https://python-poetry.org/).
- GNU Make and gcc.
- [protoc](https://grpc.io/docs/protoc-installation/), the protobuf compiler.

To configure the Python dependencies and the repo:

- Run `make install` to install the development dependencies.
- Use a virtual environment with `poetry shell`.
- Run `make init` to configure the repo.
- When coding and committing, run `make all` to run the test suite.

`make install` installs all the dependencies, including the development and
documentation dependencies, inside a virtual environment[^venv]. It uses a lock
file (`poetry.lock`) to ensure that package versions are consistent between
developers' environments.

[^venv]: Read poetry's documentation for more information on [how they are
    managed](https://python-poetry.org/docs/managing-environments/).

It also installs the project as an **editable package** inside that virtual
environment, meaning that changes to the source code are immediately reflected
in the package. The CLI is installed as `crypto-condor-cli`.

`poetry shell` activates the virtual environment inside a sub-shell that can be
exited with `ctrl+D` or by typing `exit`. This is the recommended way, as
otherwise all commands requiring the venv's python would have to be preceded by
`poetry run`.

`make all` is the go-to command for testing changes. It runs the linter, tests,
and coverage. It also builds the docs, checking for errors and running the
doctest examples, ensuring they stay up-to-date.

You can run commands normally inside this sub-shell:

```bash
# Display the CLI's help.
crypto-condor-cli --help

# Run the unit tests.
make test
```

## Design

The source code is inside the `crypto_condor` directory. It has three main
modules: `cli`, `primitives`, and `vectors`.

The `cli` is divided in commands, some of which have their own module. The main
app can be found in `main.py` and contains some generic commands (i.e. that do
not depend on a given primitive) such as `method` and `get-wrapper`.

The `primitives` are separated by modules, each with their own functions to test
implementations, protocols to describe the expected function signatures, and
enums to define the parameters (mode of operation, elliptic curve, etc.).

The `vectors` contain subdirectories where the source files for test vectors are
stored. These are parsed with the primitive's `_import.py` script and then
serialised with `protobuf`, making it easy to load them at runtime.

Finally, there is a fourth directory, `resources`. It contains the version of
the method guides that is used by the `method` commands, as well as the wrapper
templates and examples for each primitive.

### Documentation

The documentation is generated with Sphinx. Most documents are written in
Markdown, thanks to [MyST
parser](https://myst-parser.readthedocs.io/en/latest/). The exception to this
are the documents that make use of `autodoc` directives like `autofunction`, as
the `sphinx.ext.autodoc` extension doesn't support Markdown files.[^autodoc]

[^autodoc]: This may change if we migrate to the [sphinx-autodoc2
    extension](https://github.com/sphinx-extensions2/sphinx-autodoc2).

### Protobuf

We use [protobuf](https://protobuf.dev/) to store test vectors. Protobuf uses
`.proto` files that describe the message (in our case the vectors). These are
then compiled with `protoc` to Python classes. For type-checking and adding
docstrings to these classes, we use
[mypy-protobuf](https://github.com/nipunn1313/mypy-protobuf), which creates
`.pyi` files when compiling with `protoc`.

You can use the Makefile target `compile-proto` to compile the protobufs. It
finds the corresponding files, and only updates those that require it. It also
shows the `protoc` version, which should preferably be included in the commit
message.

### Testing

Testing is done with `pytest` and `pytest-cov` for code coverage. The structure
of `tests` reflects that of `crypto_condor`: tests under `primitives/` test the
functions and implementations directly, as a library user would use them, and
tests under `cli/` test the CLI commands. This includes running the wrapper
examples bundled with crypto-condor, which is especially useful as these
examples cover a lot of code, from the CLI to the primitives and test vectors.

## Adding new primitives

Here are some guidelines on how to add a new primitive. To get started, the
handy `utils/add_primitive.py` script creates templates of most of the necessary
files:

```bash
python utils/add_primitive.py <primitive name>
```

From here on out, we'll use ML-KEM as an example: since it's a recently updated
module, it is a good reference for new ones.

### Test vectors

Use the script to create:

- A protobuf descriptor:
    - Add a parameter to `Vectors` that characterises a set of tests.
    - Add the necessary fields to `Test` so any source of vectors is supported.
- A parsing script.

First, there are the test vectors. It creates a directory named `_mlkem` to
store the source files, protobuf descriptors, parsing script, and the serialized
vectors. We mainly use test vectors from [NIST
CAVP](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program)
and [Project Wycheproof](https://github.com/google/wycheproof), though any
reference (RFC, official implementation, etc.) source is welcome.

All test vectors should be serialized. To serialize test vectors we use
[Protocol Buffers](https://protobuf.dev/) or protobufs for short. You will need
two files: a protobuf descriptor and a parsing script.

The protobuf descriptor is a `.proto` file that defines the messages and their
attributes, similar to Python dataclasses. `add_primitive.py` creates it with
two types of message needed by `crypto-condor`: `Vectors` and `Test`. These
are already filled with a common set of values requiring minimal changes.
`Vectors` should define a characterising parameter (mode of operation, elliptic
curve, etc.), while `Test` should define fields that allow any source of vectors
to be added easily. This is pretty vague, but the idea is to stop having
separate types of vectors for each source, which may require a bit of additional
logic in the parsing to conform to a "standard format".

The descriptor is compiled using `protoc` to a Python module that provide the
messages as classes, which can be imported and used by the primitive module.

The parsing script will use these classes, creating a new instance for each
group of vectors, and parsing the text file to extract the values of each
vector. It also includes a `generate_json` function that is used to generate the
JSON file that declares the list of protobufs which are available for each
parameter.

### Primitive

Second, it creates the primitive module, `primitives/MLKEM.py` in this case,
where the code to test implementations will lie.

As a rule of thumb, this module includes:

- An enum which defines a parameter for the primitive (e.g. mode of operation,
  elliptic curve). This makes it easy to document (with the `autoenum`
  directive) and makes it clear which options are implemented. Also Typer uses
  enums to provide auto-completion.
- A function that loads test vectors, usually based on that enum and the JSON
  file mentioned above.
- One or more
  [Protocol](https://docs.python.org/3/library/typing.html#annotating-callable-objects)
  classes that describe the function signature that the implementation must have
  in order to be tested.
- A test function for each operation that is supported, which runs with test
  vectors or user input files.
- A function that runs a Python wrapper (or more if other languages are
  supported).

Additionally, internal implementations or wrappers of third-party
implementations are considered *private*. The convention in Python is that the
function name should start with an underscore. To improve its privacy, we do not
include this function in the module's `__dir__()` (see below). Python does not
have a way of enforcing this "privacy", users can still access these functions
if they know they exist, but the idea is to convey the message that these are
not meant to be used anywhere else, no guarantees are made.

#### A side-note on imports

Currently the primitive modules are structured to be imported and used
"directly".  For example:

```python
from crypto_condor.primitives import AES

AES.test(...)
```

We use `__dir__` to declare the public API, as it limits what is returned when
using an IDE's or interpreter's auto-completion.  This allows to remove names
such as `logging` as well as avoid exposing functions meant to be only used
internally, like our wrapper of the primitives.

`__dir__` returns a list of strings. Objects like type aliases have to be
referenced by name directly (e.g. `"CiphertextAndTag"`), while most other
objects can be referenced by their `__name__` attribute (e.g.
`verify.__name__`). The advantage of the latter is that renaming the
function/class/etc. using an IDE will change this reference automatically.

### CLI commands

Once this work on the primitive is done, add the integration to the CLI. This
should mostly consist in adding a function for the primitive under the
corresponding command, which parses the inputs with `typer.Argument` and
`typer.Option`, and passes them to the corresponding function e.g.
`MLKEM.test_encaps(...)`.

When the corresponding functions are implemented, add a new entry to the
`SUPPORTED_MODES` dictionary in `constants.py` and the necessary tests.

A few aspects to consider:

- When adding wrappers, the tool checks that the `get-wrapper` command is
  supported for the given primitive, and then looks for a directory under
  `resources/wrappers`.  This directory must be named as the primitive, in
  lower-case. Inside it the wrappers are organized by language, each with their
  own subdirectory named in lower-case.  Examples are in subdirectories named
  `<language>-example`. Each example has its own sub-subdirectory inside it.
  These sub-subdirectories are numbered by an increasing counter that starts at
  1.
- Guides are first written for the documentation then copied with the
  `utils/copy_guides.py` script.  The name matches the one for the
  documentation, namely the primitive name in upper-case.

### Adding a new harness

crypto-condor can test functions exposed by a shared library, similar to a
fuzzing hook. To do so, the functions must follow the conventions described by
the harness API. Internally, this means adding a `test_lib` function to the
corresponding primitive. This function has a particular signature:

```python
def test_lib(ffi: cffi.FFI, lib, functions: list[str]) -> ResultsDict:
    ...
```

Where:

- `ffi` is the `cffi.FFI` instance.
- `lib` is the library dlopen'd with `ffi`.
- `functions` is a list of function names to test, which should correspond to
  the primitive called.

Each primitive is in charge of calling `ffi.cdef()` to define the signature of
the exposed function, and to wrap it and test it. The
`crypto_condor.harness.test_harness` function is in charge of determining the
available functions, importing the corresponding primitives, and passing the
list of function that each primitive should test.

The documentation for this mode can be found in `docs/source/harness-api`.

### Documenting a new primitive

The documentation can be found under `docs/source`. There, it is divided in
several directories which correspond to different pages in the HTML render. As
indicated above, most documents can be written in Markdown, but those that make
use of autodoc must be written in rST as autodoc doesn't support Markdown.

## Building the documentation

The packages required to build the documentation can be installed with `poetry
install --with=docs`. Then you can either use `make docs` which builds the docs
to `docs/build/html` or use `make livedocs` with uses `sphinx-autobuild` to
build the docs, watch for changes, and reload open tabs after rebuilding
changes. Both options ensure that the dependencies are installed before
building.

For publishing, the docs are automatically built by the CI. It uses the
`pages-ci` target which calls the `all-versions` target of `docs/Makefile` is
used. This target uses a hard-coded list of Git refs (tags or branches), checks
out each ref and builds its corresponding documentation under
`docs/build/public/[ref]`. Then the `pages-ci` targets moves the resulting docs
to the correct directory used by GitLab Pages.

## Versioning

As indicated in the README, this project currently adheres to
[CalVer](https://calver.org). This version is shown in various parts of the
project (`--version` option, the documentation, the git tags, etc.). For each
release, the version must be updated in both the git tag **and**
`pyproject.toml`, otherwise the CI pipeline will fail the `publish` step.

To avoid pushing a tagged version with an out-of-date `pyproject.toml` or vice
versa, you can add a pre-push hook that runs the
`utils/check_tag_and_version.py` script. Create `.git/hooks/pre-push` with the
following content:

```bash
current=$(git branch --show-current)
if test "$current" = "main"
then
    .venv/bin/python utils/check_tag_and_version.py
fi
```

This checks that the hook only runs on the `main` branch, as others should not
be tagged. It also assumes that we are using a virtual environment to run and
test the tool, and said venv is inside the `.venv` directory.

Note: when using poetry, it might be necessary to run `poetry install` to
refresh the package version, otherwise the hook will fail.

## Contributing to CONTRIBUTING

Modifications to CONTRIBUTING must be done to the version found in
`docs/source/development/CONTRIBUTING`, as the one found in the root of the repo
is a copy of that version (see the root Makefile's `copy-contributing` target).

