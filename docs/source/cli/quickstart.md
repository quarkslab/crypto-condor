# CLI quickstart

`crypto-condor` comes with a CLI powered by Typer, which uses commands like Git
does. The commands described below all have a `--help` option to learn about the
possible options or available subcommands.

## Essentials

To start, the base command is `crypto-condor-cli`. To display the available
commands:

```bash
crypto-condor-cli
# or
crypto-condor-cli --help
```

To show the supported primitives:

```bash
crypto-condor-cli list
```

## Method guides

```{note}
The method guides are Markdown files which are used to generate the
documentation pages. As such, it is recommended to read them directly from the
documentation in order to enjoy the formatting.
```

The `method` command copies the primitive's *method guide*:

```bash
crypto-condor-cli method
```

For example, to get the AES method guide:

```bash
crypto-condor-cli method AES
```

## Test the output

The `test output` command is used to test an implementation from its output. It
has a subcommand for each primitive that is supported.

```bash
crypto-condor-cli test output
```

To test an implementation with this method it is necessary to create a file with
a specific format. This format is explained in the help message for each
primitive (as each one will have different inputs):

```bash
crypto-condor-cli test output SHA --help
```

## Test with a wrapper

The `test wrapper` command is used to test an implementation with a wrapper.

First, get the corresponding wrapper with the `get-wrapper` command.

```bash
crypto-condor-cli get-wrapper
```

The `--list` option displays the programming languages supported for each
primitive.

```bash
crypto-condor-cli get-wrapper --list
```

When you have adapted the wrapper to the implementation to test, run it with the
corresponding subcommand for that primitive.

```bash
crypto-condor-cli test wrapper --help
```

Some examples are bundled with the tool, testing the included dependencies to
show how to use the wrappers. You can get them by using the `--example` option.
The example indicates what it is testing and how to run it. For example:

```bash
crypto-condor-cli get-wrapper SHA --language Python --example 1
crypto-condor-cli test wrapper SHA sha_wrapper.py SHA-256
```

```{hint}
A list of available examples will be added. For now, consider that all wrappers
have at least one example (`--example 1`).
```

## Test with a harness

The `test harness` command is used to test a shared library that hooks the
implementation. The shared library exposes functions with specific names and
signatures so that {{ cc }} can use them to test the implementation. Once the
library is compiled, pass it to {{ cc }}:

```bash
crypto-condor-cli test harness mylib.so
```
```{hint}
For more information on this mode, see the {doc}`harness API </harness-api/index>`.
```
