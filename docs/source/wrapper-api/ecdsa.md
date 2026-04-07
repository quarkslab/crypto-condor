# ECDSA Python harness

```{currentmodule} crypto_condor.primitives.ECDSA
```

Python harnesses support all three operations: sign, verify, key generation.

To get a template using the CLI, run:

```bash
crypto-condor-cli get-wrapper ECDSA --language Python
```

To get a practical example, run:

```bash
crypto-condor-cli get-wrapper ECDSA --language Python --example 1
```

## Sign

To test an implementation of ECDSA signing, the function must:

- follow the naming convention;
- implement the `Sign` protocol.

### Naming convention

```
CC_ECDSA_sign_<curve>_<hash algo>_<key encoding>[_prehash]
```

Where:

* `curve` is one of:
* `hash algo` is one of:
* `key encoding` is one of:
* `prehash` is an optional argument, {{ cc }} will hash the message before passing it to the function.

### Protocol

```{eval-rst}
.. autoprotocol:: Sign
    :noindex:
```

## Verify

To test an implementation of ECDSA verification, the function must:

- follow the naming convention;
- implement the `Verify` protocol.

### Naming convention

```
CC_ECDSA_verify_<curve>_<hash algo>_<pubkey encoding>[_prehash]
```

Where:

* `curve` is one of:
* `hash algo` is one of:
* `pubkey encoding` is one of:
* `prehash` is an optional argument, {{ cc }} will hash the message before passing it to the function.

### Protocol

```{eval-rst}
.. autoprotocol:: Verify
    :noindex:
```
