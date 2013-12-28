# Calico
#### Strong, Fast, and Portable Authenticated Encryption

The Calico authenticated encryption library is designed to protect data sent
between two endpoints on an untrusted network.  It provides protection against
tampering of the data through replay or modification.  Calico encrypts the
data so that it cannot be read by a third party.  Calico runs in constant-time
to avoid side-channel attacks through execution timing or cache timing.

The Calico library can encrypt single packets or streams of data, so that it
can be used for UDP-based or TCP-based protocols.  It uses the most efficient
and portable methods available for speed, and it is also optimized for low-
overhead: Only 11 bytes/message.  It is also optimized to reject invalid
messages as fast as possible, roughly 5x faster than normal decryption.

Calico does not provide key agreement.  See the [Tabby](https://github.com/catid/tabby)
library for an efficient and portable implementation of key agreement.  Calico
also does not open any sockets for you - it only encodes and decodes the data.
Furthermore Calico does not consume any randomness to operate.


Benchmarks
==========

##### libcalico.a on Macbook Air (1.7 GHz Core i5-2557M Sandy Bridge, July 2011):

Output of `make test`:

~~~
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
Benchmark: Initialize() in 1.97422 usec on average / 506529 per second
+++ Test passed.

Running test 7 : Benchmark Encrypt()
Benchmark: Encrypt() 10000 bytes in 20.4203 usec on average / 489.709 MBPS / 48970.9 per second
Benchmark: Encrypt() 1000 bytes in 2.33389 usec on average / 428.469 MBPS / 428469 per second
Benchmark: Encrypt() 100 bytes in 0.35412 usec on average / 282.39 MBPS / 2.8239e+06 per second
Benchmark: Encrypt() 10 bytes in 0.19131 usec on average / 52.2712 MBPS / 5.22712e+06 per second
Benchmark: Encrypt() 1 bytes in 0.22187 usec on average / 4.50714 MBPS / 4.50714e+06 per second
+++ Test passed.

Running test 8 : Benchmark Decrypt() Rejection
Benchmark: Decrypt() drops 10000 corrupted bytes in 1.9216 usec on average / 5204 MBPS / 520400 per second
Benchmark: Decrypt() drops 1000 corrupted bytes in 0.3846 usec on average / 2600.1 MBPS / 2.6001e+06 per second
Benchmark: Decrypt() drops 100 corrupted bytes in 0.21331 usec on average / 468.801 MBPS / 4.68801e+06 per second
Benchmark: Decrypt() drops 10 corrupted bytes in 0.23418 usec on average / 42.7022 MBPS / 4.27022e+06 per second
Benchmark: Decrypt() drops 1 corrupted bytes in 0.21545 usec on average / 4.64145 MBPS / 4.64145e+06 per second
+++ Test passed.

Running test 9 : Benchmark Decrypt() Accept
Benchmark: Decrypt() 10000 bytes in 19.4561 usec on average / 513.977 MBPS / 51397.7 per second
Benchmark: Decrypt() 1000 bytes in 2.07755 usec on average / 481.336 MBPS / 481336 per second
Benchmark: Decrypt() 100 bytes in 0.39793 usec on average / 251.3 MBPS / 2.513e+06 per second
Benchmark: Decrypt() 10 bytes in 0.29607 usec on average / 33.7758 MBPS / 3.37758e+06 per second
Benchmark: Decrypt() 1 bytes in 0.27363 usec on average / 3.65457 MBPS / 3.65457e+06 per second
+++ Test passed.

Running test 10 : 2 Million Random Message Stress Test
+++ Test passed.


Test summary:
Passed 11 tests of 11

All tests passed.
~~~


Getting Started
===============

The BLAKE2 code is referenced as a submodule, so run `git submodule update --init` to download the BLAKE2 code also.

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

512-bit BLAKE2 is used to key 8-round VMAC-ChaCha,
and an anti-replay window provides replay protection.

+ BLAKE2: Full 512-bit version used as a key derivation function.
+ VMAC: Fast; a 64-bit message authentication code.
+ ChaCha: 8 rounds for less security margin and higher speed.

All algorithms are free of timing attacks (no look-up tables or branches are
taken based on the key material).

All implementations are cleanroom versions of public domain algorithms.


Unit Testing
============
The unit tests all pass valgrind.  Here's a run without valgrind on a Macbook Air:

~~~
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
~~~


Contributors
============

* Christopher A. Taylor ( mrcatid@gmail.com ) : Author
* Sam Hughes ( sam@rethinkdb.com ) : Fixed integer overflow in the API

