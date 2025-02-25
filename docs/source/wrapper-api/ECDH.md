# ECDH wrappers

## Exchange with coordinates

`exchange_coord` is a ECDH exchange using the coordinates of the public key of
the peer.

The naming convention is:

```
CC_ECDH_exchange_coord_<curve>
```

Where `curve` is one of:

- `P224`, `P256`, `P384`, `P521`
- `B283`, `B409`, `B571`

## Exchange with X509

`exchange_x509` is a ECDH exchange using the peer's public key in X509 format.

The naming convention is:

```
CC_ECDH_exchange_x509_<curve>
```

Where `curve` is one of:

- `P224`, `P256`, `P384`, `P521`
- `B283`, `B409`, `B571`
- `secp256k1`
- `brainpoolp256r1`, `brainpoolp384r1`, `brainpoolp512r1`

## Example

:::{hint}
You can get this example from the CLI:

    crypto-condor-cli get-wrapper ECDH --language Python --example 1
:::

:::{literalinclude} ../../../crypto_condor/resources/wrappers/ECDH/Python-examples/1/ecdh_wrapper_example.py
:::

## Testing the CC_ECDH class

```{attention}
This is a deprecated API that will be removed in a future version.
```

```{currentmodule} crypto_condor.primitives.ECDH
```

The `CC_ECDH` class implementing the {protocol}`ECDH`
protocol can no longer be tested through the wrapper, as the curve to test is now
encoded in the name of the functions as shown above.

However, it is still possible to test it using the Python API with the
{func}`test_exchange` function. To do so, instead of running the wrapper through the CLI
(or the {func}`test_wrapper` function), you will have to import {{ cc }} in the file and
manually call {func}`test_exchange`. For example:

```python
# ecdh_wrapper.py

# For example, test PyCryptodome.
from Crypto.Protocol import DH
from Crypto.PublicKey import ECC

# Import the ECDH module to test the implementation.
from crypto_condor.primitives import ECDH
# And import Console for pretty printing.
from crypto_condor.primitives.common import Console

console = Console()

# We define the class and properly define one of the methods to test.
class CC_ECDH:

    def exchange_nist(
        self, secret: int, pub_x: int, pub_y: int, pub_key: bytes
    ) -> bytes:
        """Test exchange with pub_key."""
        pk = ECC.import_key(pub_key, curve_name="P-256")
        sk = ECC.construct(curve="P-256", d=secret)
        return DH.key_agreement(static_priv=sk, static_pub=pk, kdf=lambda x: x)

    def exchange_wycheproof(self, secret: int, pub_key: bytes) -> bytes:
        raise NotImplementedError

# As marked in the method, we are testing the implementation over P-256.
curve = ECDH.Curve.P256

# Then call test_exchange with an instance of the class.
rd = ECDH.test_exchange(CC_ECDH(), curve)

# Use the console to display the results.
console.print_results(rd)
```

Then run the file as a script:

```bash
python ecdh_wrapper.py
```
