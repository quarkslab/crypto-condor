# RSA

{{ prolog }}

RSA is a public-key cryptosystem whose security relies on the factorization problem.

:::{list-table} Summary of ANSSI rules and recommendations
:header-rows: 1
:width: 100%

- - Rule/recommendation
  - Comments
- - {ref}`RegleFactorisation <rsaes-regle-factorisation>`
  -
    - Before 2031: modulus $\ge 2048$ bits long.
    - From 2031: modulus $\ge 3072$ bits long.
    - size(secret exponents) = size(modulus).
    - For encryption, public exponents $> 65536.
- - {ref}`RecommandationFactorisation <rsaes-rec-factorisation>`
  -
    - Modulus $\ge 3072$ bits long.
    - Public exponents $> 65536$.
    - size($p$) = size($q$), and must be chosen uniformly at random.
- - {ref}`RecommandationChiffAsym <rsaes-rec-chiff-asym>`
  -
    - {green}`Compliant`: RSAES-OAEP defined in [PKCS#1 v2.1][PKCSv2_1] is
    compliant as long as {ref}`RegleFactorisation <rsaes-regle-factorisation>`
    is followed.
    - {red}`Not compliant`: RSAES as defined in [PKCS#1 v1.5][PKCSv1_5] is not
    compliant if it's possible to use a padding oracle, see [Ble98][Ble98].
- - {ref}`RecommandationSignAsym <rsaes-rec-sign-asym>`
  -
    - {green}`Compliant`:  RSA-SSA-PSS as defined in [PKCS#1 v2.1][PKCSv2_1] is
    compliant as long as {ref}`RegleFactorisation <rsaes-regle-factorisation>`
    is followed.
    - {red}`Not compliant`: RSASSA as defined in [PKCS#1 v1.5][PKCSv1_5] is not
    compliant when the public exponent $e$ is small, and for a poor choice of
    implementation of the signature verification linked to the padding (see
    [Ble06][Ble06]).

:::

## Signature schemes

{rfc}`8017` defines two signature schemes: RSASSA-PSS and RSASSA-PKCS1-v1_5. It
states that "Although no attacks are known against RSASSA-PKCS1-v1_5, in the
interest of increased robustness, RSASSA-PSS is REQUIRED in new applications.
RSASSA-PKCS1-v1_5 is included only for compatibility with existing
applications". SSA stands for Signature Scheme with Appendix.

Since the signatures are computed on the output of hash functions, there is
virtually no limit to the size of the message to sign depending on the
underlying hash function.

In both schemes:

- The signature generation function takes as input the private key and the
  message to sign.  It returns the resulting signature.
- The signature verification function takes as input the public key, the signed
  message, and the signature. It returns either "valid signature" or "invalid
  signature".
- The choice of a hash function parametrizes the operations.

### RSASSA-PSS

[RSASSA-PSS](https://datatracker.ietf.org/doc/html/rfc8017#section-8.1) gets its
name from the EMSA-PSS encoding method, which is based on Bellare's and
Rogaway's [Probabilistic Signature
Scheme](https://www.cs.ucdavis.edu/~rogaway/papers/exact.pdf).  As the name
indicates, there is a probabilistic component: a randomly generated salt is
used. As RSAES-OAEP, it is also parametrized by the choice of a hash function to
use with the mask generating function and the choice of a salt length.

When verifying a signature, the operation extracts both the salt and the hash
output of the encoded message.  These must be consistent with the given message
for the signature to be considered valid.

### RSASSA-PKCS1-v1_5

[RSASSA-PKCS1-v1_5](https://datatracker.ietf.org/doc/html/rfc8017#section-8.2)
uses a deterministic encoding operation, unlike RSASSA-PSS. This means that for
verifying signatures, the operation applies the encoding operation to the given
message, and compares this with the encoded message recovered from the
signature. The signature is considered valid if they are equal.

## Encryption schemes

Plain RSA encryption should not be used, as there are a [number of
attacks](https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Attacks_against_plain_RSA)
against it. Instead, {rfc}`8017#7` defines two encryption schemes: the modern
and recommended RSAES-OAEP and the deprecated RSAES-PKCS1-v1_5.

### RSAES-OAEP

[RSAES-OAEP](https://datatracker.ietf.org/doc/html/rfc8017#section-7.1) uses
Bellare's and Rogaway's [Optimal Asymmetric Encryption
Padding](https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding).

According to {rfc}`8017` "RSAES-OAEP is parameterized by the choice of hash
function and mask generation function". The mask generation function commonly
used is called MGF1, which is itself parametrized by the choice of a hash
function and the length of the salt used.

The encryption function takes as input the public key $(n,e)$, the message to
encrypt, and an optional label, which is an empty string by default. The message
must be at most $k-2hLen-2$ bytes long, where $k$ is the size of the modulus $n$
and $hLen$ is the length of the output of the underlying hash function. It
returns the resulting ciphertext.

The decryption function takes as input the secret key, the ciphertext to
decrypt, and the optional label. It returns the resulting plaintext.

### RSAES-PKCS1-v1_5

[RSAES-PKCS1-v1_5](https://datatracker.ietf.org/doc/html/rfc8017#section-7.2)
uses the encoding method defined in version 1.5 of PKCS#1. RFC 8017 states that
"the use of this scheme for encrypting an arbitrary message, as opposed to a
randomly generated key, is NOT RECOMMENDED".

Considering the numerous attacks to which an implementation of this scheme may
be vulnerable, such as [Bleichenbacher's][Ble98], [an attack on a low-exponent
RSA](https://link.springer.com/content/pdf/10.1007/3-540-68339-9_1.pdf), and
[more](https://www.iacr.org/archive/eurocrypt2000/1807/18070374-new.pdf), the
use of this scheme is not recommended.

The encryption function takes as input the public key $(n, e)$ and the message
to encrypt, whose length must be less than $k - 1$, where $k$ is the size of the
modulus $n$. It returns the resulting ciphertext.

The decryption function takes as input the private key and the ciphertext to
decrypt, whose length is at most $k$. It returns the resulting plaintext.

## ANSSI rules and recommendations

> Source: [ANSSI - Guide des mécanismes cryptographiques](https://www.ssi.gouv.fr/uploads/2021/03/anssi-guide-mecanismes_crypto-2.04.pdf)

### Factorisation

:::{admonition} RègleFactorisation
:class: attention
:name: rsaes-regle-factorisation

1. The minimum size of the modulus is 2048 bits, for use no later than the end
   of 2023.
2. For use beyond 2031, the minimum size of the modulus is 3072 bits.
3. The secret exponents must be the same size as the modulus.
4. For encryption, the public exponents must be greater than $2^{16} = 65536$.
:::

:::{admonition} RecommandationFactorisation
:name: rsaes-rec-factorisation

1. It is recommended to use modulus of at least 3072 bits, even for use no later
   than 2030.
2. It is recommended, for all applications, the use of public exponents greater
   than $2^{16} = 65536$.
3. It is recommended that the two prime numbers $p$ and $q$ that make up the
   modulus are of the same size and are chosen uniformly at random.
:::

### Asymmetric encryption

:::{admonition} RecommandationChiffAsym
:name: rsaes-rec-chiff-asym

1. It is recommended to use provably secure asymmetric encryption mechanisms.
:::

:::{admonition} RecommandationSignAsym
:name: rsaes-rec-sign-asym

1. It is recommended to use provably secure asymmetric signature schemes.
:::

:::{admonition} RegleGestAsym
:class: attention
:name: rsaes-regle-gest-asym

1. The same asymmetric key pair may not be used for more than one purpose.
2. Hierarchically important keys, such as root keys, must be generated and used
   by compliant mechanisms.
:::

<!-- References -->
[Ble06]: https://mailarchive.ietf.org/arch/msg/openpgp/5rnE9ZRN1AokBVj3VqblGlP63QE/
[Ble98]: https://archiv.infsec.ethz.ch/education/fs08/secsem/bleichenbacher98.pdf
[PKCSv1_5]: https://datatracker.ietf.org/doc/html/rfc2313
[PKCSv2_1]: https://datatracker.ietf.org/doc/html/rfc3447
