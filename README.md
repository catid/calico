Calico
======

Calico :: C++ Authenticated Encryption Library

The goal of Calico is to provide a sleak and speedy alternative to rolling your
own authenticated encryption.  Calico is designed to encrypt small messages in
memory before transmitting them over a UDP socket for low-latency applications.

Calico is not a complete data security solution like OpenSSL.  Calico can be
used as a component to build a secure tunnel over the Internet:  Usually two
endpoints will share a secret key during a key agreement handshake.  After this
happens, Calico can step in to encrypt and decrypt the session data.  Because
it provides authenticated encryption, that means that it also prevents any
tampering of the data.

Calico only provides the math to make this happen; it does not open sockets or
send packets over the Internet.  It will only encrypt or decrypt in memory, and
then it will be the user's responsibility to transmit the result.  As a result
it has no dependencies and is easy to reuse.

Calico is not designed for use with TCP streams.  I do have a good design for
supporting streams but it is not implemented because there is no need for it
in any of the projects I am working on.  If you would like a stream mode just
ask and I could turn one around in a couple of days.


Why?
====

These days it seems everyone wants a ready-made package to just plug into their
app and go.  So, this project is for the people who write those packages.  It
provides good, modern approaches to authenticated encryption while remaining a
small and focused codebase that you can just drop into your own software.

Please consider this instead of using something slower with more overhead.
And if you are rolling your own encryption code please use this one as a basis
instead, because it does a lot of things right that are easy to botch, speaking
from years of experience writing these sorts of libraries.


Benchmarks
==========

    Mac OS X 10.7.4 (2.7 GHz Intel Core i5) 
     $ uname -a
    Darwin kuang.local 11.4.0 Darwin Kernel Version 11.4.0: Mon Apr  9 19:32:15 PDT 2012; root:xnu-1699.26.8~1/RELEASE_X86_64 x86_64
    $ clang++ --version
    Apple clang version 3.1 (tags/Apple/clang-318.0.58) (based on LLVM 3.1svn)
    Target: x86_64-apple-darwin11.4.0
    Thread model: posix

    Using -O4:

    Benchmark: Encrypt() 10000 bytes in 16.0811 usec on average / 621.847 MBPS / 62184.7 per second
    Benchmark: Encrypt() 1000 bytes in 1.64204 usec on average / 608.999 MBPS / 608999 per second
    Benchmark: Encrypt() 100 bytes in 0.2316 usec on average / 431.779 MBPS / 4.31779e+06 per second
    Benchmark: Encrypt() 10 bytes in 0.13549 usec on average / 73.8062 MBPS / 7.38062e+06 per second
    Benchmark: Encrypt() 1 bytes in 0.13842 usec on average / 7.22439 MBPS / 7.22439e+06 per second

    Benchmark: Decrypt() drops 10000 corrupted bytes in 1.35998 usec on average / 7353.05 MBPS / 735305 per second
    Benchmark: Decrypt() drops 1000 corrupted bytes in 0.25143 usec on average / 3977.25 MBPS / 3.97725e+06 per second
    Benchmark: Decrypt() drops 100 corrupted bytes in 0.15385 usec on average / 649.984 MBPS / 6.49984e+06 per second
    Benchmark: Decrypt() drops 10 corrupted bytes in 0.13845 usec on average / 72.2282 MBPS / 7.22282e+06 per second
    Benchmark: Decrypt() drops 1 corrupted bytes in 0.13805 usec on average / 7.24375 MBPS / 7.24375e+06 per second

    Benchmark: Decrypt() 10000 bytes in 14.9429 usec on average / 669.216 MBPS / 66921.6 per second
    Benchmark: Decrypt() 1000 bytes in 1.6471 usec on average / 607.128 MBPS / 607128 per second
    Benchmark: Decrypt() 100 bytes in 0.31462 usec on average / 317.844 MBPS / 3.17844e+06 per second
    Benchmark: Decrypt() 10 bytes in 0.20617 usec on average / 48.5037 MBPS / 4.85037e+06 per second
    Benchmark: Decrypt() 1 bytes in 0.20806 usec on average / 4.80631 MBPS / 4.80631e+06 per second


Getting Started
===============

The API has three functions:

+ result = Initialize(key, name, mode)

	Initialize() sets up one end of the tunnel.

	The 256-bit key must only be used once ever, and then thrown away.
	The name is used to create multiple tunnels from a single key.
	The mode selects whether it is the initiator or responder.

+ len = Encrypt(plaintext, bytes, ciphertext, bytes)

	Encrypt() will encrypt some data, adding overhead for validation.
	It returns the length of the result.

+ len = Decrypt(ciphertext, bytes)

	Decrypt() will decrypt some encrypted data, removing the overhead.
	It decrypts in-place and returns the length of the result.

See the Example.cpp source file for basic usage.


Cryptographic Primitives
========================

256-bit Skein in KDF mode is used to key 8-round VMAC-ChaCha,
and an anti-replay window provides replay protection.

+ Skein: Full 256-bit version used as a key derivation function.
+ VMAC: Fast; a 64-bit message authentication code.
+ ChaCha: 8 rounds for less security margin and higher speed.

All algorithms are free of timing attacks (no look-up tables or branches are
taken based on the key material).

All implementations are cleanroom versions of public domain algorithms.

TODO: Add test vectors and unit tests for each algorithm to demonstrate that
these are faithful implementations without failure modes.


Discussion
==========

To use this effectively there needs to be a good key agreement protocol to
go along with it.  I have written several over the years, but my libraries are
not portable.  Watch this space; I may decide to release key agreement as a
separate library and try to make it portable.


Unit Testing
============
The unit tests all pass valgrind.  Here's a run without valgrind on a Macbook Air:

    Running test 0 : Uninitialized
    +++ Test passed.

    Running test 1 : Data Integrity
    +++ Test passed.

    Running test 2 : Integer Overflow Input
    +++ Test passed.

    Running test 3 : Wrong Key
    +++ Test passed.

    Running test 4 : Replay Attack
    +++ Test passed.

    Running test 5 : Replay Window
    +++ Test passed.

    Running test 6 : Benchmark Initialize()
    Benchmark: Initialize() in 4.54089 usec on average / 220221 per second
    +++ Test passed.

    Running test 7 : Benchmark Encrypt()
    Benchmark: Encrypt() 10000 bytes in 20.2912 usec on average / 492.824 MBPS / 49282.4 per second
    Benchmark: Encrypt() 1000 bytes in 2.12911 usec on average / 469.68 MBPS / 469680 per second
    Benchmark: Encrypt() 100 bytes in 0.33175 usec on average / 301.432 MBPS / 3.01432e+06 per second
    Benchmark: Encrypt() 10 bytes in 0.19721 usec on average / 50.7074 MBPS / 5.07074e+06 per second
    Benchmark: Encrypt() 1 bytes in 0.19816 usec on average / 5.04643 MBPS / 5.04643e+06 per second
    +++ Test passed.

    Running test 8 : Benchmark Decrypt() Rejection
    Benchmark: Decrypt() drops 10000 corrupted bytes in 1.76228 usec on average / 5674.47 MBPS / 567447 per second
    Benchmark: Decrypt() drops 1000 corrupted bytes in 0.3495 usec on average / 2861.23 MBPS / 2.86123e+06 per second
    Benchmark: Decrypt() drops 100 corrupted bytes in 0.21187 usec on average / 471.988 MBPS / 4.71988e+06 per second
    Benchmark: Decrypt() drops 10 corrupted bytes in 0.20319 usec on average / 49.215 MBPS / 4.9215e+06 per second
    Benchmark: Decrypt() drops 1 corrupted bytes in 0.20454 usec on average / 4.88902 MBPS / 4.88902e+06 per second
    +++ Test passed.

    Running test 9 : Benchmark Decrypt() Accept
    Benchmark: Decrypt() 10000 bytes in 19.3794 usec on average / 516.012 MBPS / 51601.2 per second
    Benchmark: Decrypt() 1000 bytes in 2.1582 usec on average / 463.349 MBPS / 463349 per second
    Benchmark: Decrypt() 100 bytes in 0.45164 usec on average / 221.415 MBPS / 2.21415e+06 per second
    Benchmark: Decrypt() 10 bytes in 0.32348 usec on average / 30.9138 MBPS / 3.09138e+06 per second
    Benchmark: Decrypt() 1 bytes in 0.31879 usec on average / 3.13686 MBPS / 3.13686e+06 per second
    +++ Test passed.

    Running test 10 : 2 Million Random Message Stress Test
    +++ Test passed.


    Test summary:
    Passed 11 tests of 11

    All tests passed.


Contributors
============

* Christopher A. Taylor ( mrcatid@gmail.com ) : Author
* Sam Hughes ( sam@rethinkdb.com ) : Fixed integer overflow in the API
