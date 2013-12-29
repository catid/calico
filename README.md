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
messages as quickly as possible, roughly 4x faster than normal decryption.

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
Running test 6 : Benchmark Initialize()
Benchmark: Initialize() in 0.72452 usec on average / 1.38022e+06 per second
+++ Test passed.

Running test 7 : Benchmark Encrypt()
Benchmark: Encrypt() 10000 bytes in 10.585 usec on average / 944.734 MBPS / 94473.4 per second
Benchmark: Encrypt() 1000 bytes in 1.36371 usec on average / 733.294 MBPS / 733294 per second
Benchmark: Encrypt() 100 bytes in 0.4026 usec on average / 248.385 MBPS / 2.48385e+06 per second
Benchmark: Encrypt() 10 bytes in 0.24678 usec on average / 40.5219 MBPS / 4.05219e+06 per second
Benchmark: Encrypt() 1 bytes in 0.18078 usec on average / 5.53159 MBPS / 5.53159e+06 per second
+++ Test passed.

Running test 8 : Benchmark Decrypt() Rejection
Benchmark: Decrypt() drops 10000 corrupted bytes in 1.96555 usec on average / 5087.63 MBPS / 508763 per second
Benchmark: Decrypt() drops 1000 corrupted bytes in 0.38561 usec on average / 2593.29 MBPS / 2.59329e+06 per second
Benchmark: Decrypt() drops 100 corrupted bytes in 0.18851 usec on average / 530.476 MBPS / 5.30476e+06 per second
Benchmark: Decrypt() drops 10 corrupted bytes in 0.20704 usec on average / 48.2998 MBPS / 4.82998e+06 per second
Benchmark: Decrypt() drops 1 corrupted bytes in 0.18693 usec on average / 5.3496 MBPS / 5.3496e+06 per second
+++ Test passed.

Running test 9 : Benchmark Decrypt() Accept
Benchmark: Decrypt() 10000 bytes in 10.9359 usec on average / 914.423 MBPS / 91442.3 per second
Benchmark: Decrypt() 1000 bytes in 1.56365 usec on average / 639.529 MBPS / 639529 per second
Benchmark: Decrypt() 100 bytes in 0.47076 usec on average / 212.422 MBPS / 2.12422e+06 per second
Benchmark: Decrypt() 10 bytes in 0.30794 usec on average / 32.4739 MBPS / 3.24739e+06 per second
Benchmark: Decrypt() 1 bytes in 0.31074 usec on average / 3.21812 MBPS / 3.21812e+06 per second
+++ Test passed.
~~~

When over 1000 messages can be encrypted/decrypted in under a millisecond, encryption should not
be a bottleneck for any network application.

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

chacha-opt/chacha.h
chacha-opt/chacha.c

And a chacha implementation, for example:
chacha-opt/chacha_blocks_ref.c
chacha-opt/chacha_blocks_ssse3-64.S
~~~

It should port well to any platform, since it does not use any inline assembly or OS-specific APIs.

The reference version of ChaCha is good enough for a standard portable codebase, though to get good
server performance you should pick the best version for your target.

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
than Poly1305.  The 64-bit hash value is encrypted with some of the ChaCha-14 keystream from the end
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
Intel x64 machines.  The AES-NI instruction is almost twice as slow as this software.


## Credits

This software was written entirely by myself ( Christopher A. Taylor <mrcatid@gmail.com> ).  If you
find it useful and would like to buy me a coffee, consider [tipping](https://www.gittip.com/catid/).

Thanks to Sam Hughes ( sam@rethinkdb.com ) for fixing an integer overflow vulnerability in an
early version of the software.

