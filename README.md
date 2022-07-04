Anroid applicaton development project
=====

What is this project ?
------------

Dependencies
------------

- *bctoolbox[1]*: portability layer and crypto function abstraction
- *bzrtp[2]*: open source implementation of ZRTP keys exchange protocol
- *mbedtls[3]*: library that implements cryptographic primitives, X.509 certificate manipulation and the SSL/TLS and DTLS protocols
- *dilithium[4]*: library that implements the dilithium algorithm by PQClean and validated by NIST. Used for SAS signature
- *kyber[5]*: library that implements the kyber algorithm by PQClean and validated by NIST. Used for post-quantum secret exchange during the Diffie-Hellman exchange

Repertories
------------

- *FirstProgramm*: Repertories where we can make an exchange between two correspondants. Sas signature is implemented with dilithium. Post-quantum secret exchange is implemented with Kyber
- *socketProgramm*: Repertories where we can make an exchange between a server and a client. We can only now exchange string
- *testDilithium*: Repertories where we tested the Dilithium signature algorithm
- *testEcdsa*: Repertories where we tested the Ecdsa signature algorithm
- *testKyber*: Repertories where we tested the Kyber post-quantum secret exchange algorithm