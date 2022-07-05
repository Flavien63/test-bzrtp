Development of a post-quantum mobile application
=====

What is this project ?
------------

This project is an internship subject within Orange Labs. Initially, the objective of the internship is to implement post-quantum security in the ZRTP protocol. It is done in the *bzrtp* directory which is the bzrtp library modified to add a SAS signature and a post-quantum secret exchange. After that, we used the modified library for a simple exchange between two correspondents in the *simpleExchange* directory. Then we will use it in the *socketProgramm* directory for an exchange between two clients. The second objective is to develop a mobile application to make calls between two correspondents using this protocol.

Dependencies
------------

- *bctoolbox[1]*: portability layer and crypto function abstraction
- *bzrtp[2]*: open source implementation of ZRTP keys exchange protocol
- *mbedtls[3]*: library that implements cryptographic primitives, X.509 certificate manipulation and the SSL/TLS and DTLS protocols
- *dilithium[4]*: library that implements the dilithium algorithm by PQClean and validated by NIST. Used for SAS signature
- *kyber[5]*: library that implements the kyber algorithm by PQClean and validated by NIST. Used for post-quantum secret exchange during the Diffie-Hellman exchange

Directories
------------

- *bzrtp*: Directory of the modified library bzrtp. Include the SAS signature and the post-quantum secret exchange
- *simpleExchange*: Directory where we can make an exchange between two correspondants. Sas signature is implemented with dilithium. Post-quantum secret exchange is implemented with Kyber. To compile, we need bzrtp to be compiled
- *socketProgramm*: Directory where we can make an exchange between a server and a client. We can only now exchange string
- *testDilithium*: Directory where we tested the Dilithium signature algorithm
- *testEcdsa*: Directory where we tested the Ecdsa signature algorithm
- *testKyber*: Directory where we tested the Kyber post-quantum secret exchange algorithm

Build 
------------

bzrtp
-----------

    cd bzrtp
    ./autogen.sh && ./configure && make && sudo make install

simpleExchange
-----------

    cd simpleExchange
    cd mbedtls
    cmake .
    make
    sudo make install
    cd ../
    cd bctoolbox
    cmake .
    make
    sudo make install
    cd ../
    make
    ./prog ou valgrind ./prog

SocketProgramm
-----------

    clang serveur.c -o Alice -Wall -Wextra -g
    clang client.c -o Bob -Wall -Wextra -g
    ./serveur {Port number}
    ./client localhost {Port number}

testDilithium
-----------

    make
    ./prog ou valgrind ./prog

testEcdsa
-----------

    make
    ./prog ou valgrind ./prog

testKyber
-----------

    make
    ./prog ou valgrind ./prog

