# ECDH

{{ prolog }}

Elliptic Curve Diffie-Hellman is a key agreement protocol involving elliptic
curve cryptography. It was standardised by NIST in [SP
800-56A](https://csrc.nist.gov/pubs/sp/800/56/a/r3/final).

:::{csv-table} Summary of ANSSI rules and recommendations
:header: Rules, Comments

"{ref}`RègleECp <ecdh-regle-ecp>`", "{green}`Compliant` with FRP256v1, P-256, P-384, P-521, brainpoolP256r1, brainpoolP384r1, brainpoolP512r1."
"{ref}`RecommandationECp <ecdh-rec-ecp>`", "See curves above."
"{ref}`RegleEC2 <ecdh-regle-ec2>`", "{green}`Compliant` with B-283, B-409, B-571."
"{ref}`RecommandationEC2 <ecdh-rec-ec2>`", "See curves above."
"{ref}`RèglePQNonRégression <ecdh-regle-pq-non-regression>`", "{green}`Compliant` if the curve is compliant with RègleECp or RègleEC2."
"{ref}`RègleGestAsym <ecdh-regle-gest-asym>`", "Up to the implementation."
:::

## Overview

As a key agreement protocol, ECDH involves two parties who want to establish a
shared secret using asymmetric cryptography. They start by agreeing on the
domain parameters to use.

:::{csv-table} ECDH domain parameters
:header-rows: 1

"Parameter", "Description"
"$p$", "The prime which specifies the size of the finite field."
"$a$, $b$", "The coefficients of the elliptic curve equation."
"$G$", "The base point, generator of the subgroup."
"$n$", "The order of the subgroup."
"$h$", "The cofactor."
:::

These parameters are usually already defined by a *named curve* such as P-256. A good
resource for finding the parameters of a named curve is
[neuromancer.sk/std](https://neuromancer.sk/std/): for example, here is the page for
[P-256](https://neuromancer.sk/std/nist/P-256).

Once the domain parameters have been agreed upon, both parties, hereby
called Alice and Bob, proceed as follows:

1. Alice picks $d_A$ randomly.
2. Bob picks $d_B$ randomly.
3. Alice sends $pub_A = d_A * G$ to Bob.
4. Bob sends $pub_B = d_B *G$ to Alice.
5. Alice computes $P = d_A * pub_B = d_A * d_B * G$.
6. Bob computes $P = d_B * pub_A = d_B * d_A * G$.

At the end of this procedure, both Alice and Bob obtained the same point $P$.
The shared secret is the x-coordinate of this point.

However the algorithm standardised in SP 800-56A is slightly different: called
ECC CDH (Elliptic Curve Cryptography Cofactor Diffie-Hellman), it involves
introducing the cofactor $h$ to the mix in the steps 5 and 6:

5. Alice computes $P = (d_A * h) * pub_B$.
6. Bob computes $P = (d_B * h) * pub_A$.

## ANSSI rules and recommendations

> Source: [Guide des mécanismes cryptographiques](https://cyber.gouv.fr/sites/default/files/2021/03/anssi-guide-mecanismes_crypto-2.04.pdf)

### Discrete logarithm for elliptic curves defined over $GF(p)$

:::{admonition} RègleECp
:class: attention
:name: ecdh-regle-ecp

- Use subgroups whose order is a multiple of a prime number that is at least 250
  bits long.
    1. When using curves whose security relies of a mathematical problem that is
       easier than the generic elliptic curve discrete logarithm problem for
       elliptic curves defined over $GF(p)$, the problem must verify the
       corresponding rules.
:::

:::{admonition} RecommandationECp
:name: ecdh-rec-ecp

1. It is recommended to use subgroups whose order is prime (instead of being a
   multiple of a prime number).
:::

### Discrete logarithm for elliptic curves defined over $GF(2^n)$

:::{admonition} RègleEc2
:class: attention
:name: ecdh-regle-ec2

1. The order of the subgroup must be a multiple of a prime number that is at
   least 250 bits long.
2. The parameter {math}`n` must be a prime number.
3. When using curves whose security relies of a mathematical problem that is
   easier than the generic elliptic curve discrete logarithm problem for
   elliptic curves defined over {math}`GF(2^n)`, the problem must verify the
   corresponding rules.
:::

:::{admonition} RecommandationEC2
:name: ecdh-rec-ec2

1. It is recommended to use subgroups whose order is prime (instead of being the
   multiple of a prime).
:::

### Post-quantum resistance

:::{admonition} RèglePQNonRégression
:class: attention
:name: ecdh-regle-pq-non-regression

The security of asymmetric cryptosystems must depend on at least a mathematical
problem that has been well studied and recognized by academia.
:::


### Key management

:::{admonition} RègleGestAsym
:class: attention
:name: ecdh-regle-gest-asym

1. The same asymmetric key pair may not be used for more than one purpose.
2. Hierarchically important keys, such as root keys, must be generated and used
   by compliant mechanisms.
:::

## ANSSI notes and recommendations

> Source: [Guide de sélection d'algorithmes cryptographiques](https://cyber.gouv.fr/sites/default/files/2021/03/anssi-guide-selection_crypto-1.0.pdf)

:::{admonition} Note 5.3.a: Points on the curve
:class: attention
:name: ecdh-note-5-3-a

Concerning brainpoolP256r1, brainpoolP384r1, brainpoolP512r1, P-256, P-384, and
P-521:

For curve parameters such that all points on the curve are multiples of the base
point $P$ of prime order $q$, implementations must verify that the points used
belong to the curve, in other words that the points verify the equation defining
the curve.
:::

