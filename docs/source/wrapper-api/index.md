# Wrapper API

Each module defines the primitive operations it can test. These operations can
be tested through the Python wrappers by defining functions with specific names
and signatures. The function names encode encode the primitive, operation, and
parameters to test, while the signature must conform to the corresponding
protocol.

:::{toctree}
:maxdepth: 1

AES <AES>
ECDH <ECDH>
HMAC <HMAC>
HQC <HQC>
SHA <SHA>
SHAKE <SHAKE>
SLH-DSA <SLHDSA>
:::
