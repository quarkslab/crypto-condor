# Solution to the blog post exercise

> See: [https://blog.quarkslab.com/crypto-condor-a-test-suite-for-cryptographic-primitives.html](https://blog.quarkslab.com/crypto-condor-a-test-suite-for-cryptographic-primitives.html)

Here's an overview of how to arrive to this solution.

1. Install `crypto-condor` from PyPI:

```bash
python -m pip install crypto-condor
```

2. Clone the [repo](https://github.com/ANSSI-FR/cry-me).
3. To get the sources without spoilers, `cd` to `cryme_app` and run `make
   app_bundle_src`.
4. From the resulting `cry.me.src.bundle.tar.gz`, copy the `aes`, `sha`, and
   `utilities` directories from `olm-sdk/sources/lib/crypto-algorithms` to the
   directory where this README and Makefile are.
5. Get the AES and SHA wrappers:

```bash
crypto-condor-cli get-wrapper AES --language C
crypto-condor-cli get-wrapper SHA --language C
```

6. Fill them by reading the header files to figure out how to use the
   implementations, see the comments marked `SOL` for explanations. Then run
   `make test` to compile them and run the tests. The expected result is that
   the tests run (they don't crash) and they all fail.
7. Bonus: find *why* the implementations are not compliant, fix the issues (two
   per primitive), and test your solution with the wrappers. :)
