# Calico
#### Strong, Fast, and Portable Authenticated Encryption

The Calico authenticated encryption library is designed to protect data sent
between two endpoints on an untrusted network.  It provides protection against
tampering of the data through replay or modification.  Calico encrypts the
data so that it cannot be read by a third party.  Calico runs in constant-time
to avoid side-channel attacks through execution timing or cache timing.

The Calico library can encrypt single packets or streams of data, so that it
can be used for UDP-based or TCP-based protocols.  It uses the most efficient
and portable methods available for speed, and it is also optimized for low
overhead: Only 11 bytes/message.  It is also optimized to reject invalid
messages as quickly as possible, roughly 5x faster than normal decryption.

Calico does not provide key agreement.  See the [Tabby](https://github.com/catid/tabby)
library for an efficient and portable implementation of key agreement.  Calico
also does not open any sockets for you - It only encodes and decodes the data.
Calico does not consume any randomness to operate.

Calico uses Chacha-20 for key expansion, ChaCha-14 for encryption, and VMAC
for message authentication.


## Benchmarks

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

These tests were also re-run with valgrind, which took a lot longer. =)

## Usage

#### Example Usage

For example usage, check out the [example test](https://github.com/catid/calico/blob/master/tests/calico_example.cpp).

For more thorough usage, check out the [unit tester code](https://github.com/catid/calico/blob/master/tests/calico_test.cpp).

#### Building: Mac

Simply run `make test`:  The output will be under `bin/libcalico.a`.  And it will run the unit-tester.

#### Building: Other

The [libcat](https://github.com/catid/libcat) and [chacha-opt](https://github.com/floodyberry/chacha-opt)
libraries are referenced as submodules, so run `git submodule update --init` to download these dependencies.

The following files are required to build Calico:

~~~
src/*

libcat/BitMath.*
libcat/EndianNeutral.*
libcat/SecureErase.*

libcat/Platform.hpp
libcat/Config.hpp

TODO: chacha-opt files
~~~

It should port well to any platform, since it does not use any inline assembly or OS-specific APIs.

#### API Reference

Please refer to the [Calico header file](https://github.com/catid/calico/blob/master/include/calico.h)
for the API reference.


## Details

The single 32 byte key provided to `calico_key` is expanded into keys for VHash, the first outgoing
IV, and the 32 byte ChaCha-14 key.  Each side gets their own set of unique keys.  And each side
decides which of the keys to use, based on the `role` parameter: Either `CALICO_INITIATOR` or
`CALICO_RESPONDER`.

During encryption, ChaCha-14 is keyed with the endpoint's key and with the message's unique IV number,
which increments by 1 for each outgoing message.  The IV is truncated to the low 3 bytes and will be
reconstructed by the other party based on the most recently accepted IV.  The IV value is also
obfuscated to make the resulting ciphertext look more random.  The message is encrypted, and the
encrypted message is hashed with VHash.  VHash is a 64-bit Wegman-Carter hash with faster performance
than Poly1306.  The 64-bit hash value is encrypted with some of the ChaCha-14 keystream from the end
of the first 128-byte block to protect it and turn it into a secure message authentication code.

The obfuscated 3-byte IV is reconstructed by the recipient based on the most recently accepted IV.
The IV value is validated to verify that a message with the same IV has not been received already to
avoid replay attacks.  Using this IV and the sender's key, ChaCha-14 is keyed to generate the first
128-byte block of keystream.  To reject invalid messages more quickly, the VHash value is recovered
before decrypting the message and it is reconstructed by the recipient and verified to match.
After the VMAC is validated, the message is decrypted in-place.

All algorithms are free of timing attacks; no look-up tables or branches are taken based on the keys.

To optimize the ChaCha function for servers and reduce the impact of using strong cryptography, the
[chacha-opt](https://github.com/floodyberry/chacha-opt) implementation is employed when running on
Intel x64 servers, which puts it on par with the built-in AES instruction.  AES was not used because
it is exceptionally complex to implement for mobile devices in software, and ChaCha is much
faster in software and much easier to audit due to its simplicity.


## Credits

This software was written entirely by myself ( Christopher A. Taylor <mrcatid@gmail.com> ).  If you
find it useful and would like to buy me a coffee, consider [tipping](https://www.gittip.com/catid/).

Thanks to Sam Hughes ( sam@rethinkdb.com ) for fixing an integer overflow vulnerability in an
early version of the software.

