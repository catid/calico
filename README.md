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
overhead: Only 11 bytes per datagram or 8 bytes per stream message.  Calico
rejects invalid messages as quickly as possible -- roughly 4x faster than
normal decryption.

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

##### Building: Windows

You can link to the 64-bit `bin/libcalico.lib` static library and include
`include/calico.h` to use Calico from an e.g. Visual Studio project.
There is an example test project under `msvc2010/` that demonstrates using
Calico from a Visual Studio project.

The following instructions allow you to reproduce the `bin/libcalico.lib` binary:

Download LLVM from [http://llvm.org/builds/](http://llvm.org/builds/) for Windows to C:\LLVM\.
Download Mingw64 from [http://mingw-w64.sourceforge.net/](http://mingw-w64.sourceforge.net/) for Windows 64-bit to C:\mingw64\.

~~~
copy Makefile.Mingw64 Makefile
c:\mingw64\bin\mingw32-make.exe release
~~~

This produces `bin/libcalico.lib`, which can be linked to an MSVC2010 build.

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
IV, and the 32 byte ChaCha-14 key, for both the stream and the datagram modes.  Each mode gets its
own first IV and key.  Each side gets their own set of unique keys.  And each side decides which of
the keys to use, based on the `role` parameter: Either `CALICO_INITIATOR` or `CALICO_RESPONDER`.

During encryption, ChaCha-14 is keyed with the endpoint's key and with the message's unique IV number,
which increments by 1 for each outgoing message.  The IV is truncated to the low 3 bytes and will be
reconstructed by the other party based on the most recently accepted IV.  The IV value is also
obfuscated to make the resulting ciphertext look more random.  The message is encrypted, and the
encrypted message is hashed with VHash.  VHash is a fast keyed 64-bit hash.  The 64-bit hash value is
encrypted with some of the ChaCha-14 keystream from the end of the first 128-byte block to protect it
and turn it into a secure Wegman-Carter message authentication code.

On the receiver side, the obfuscated 3-byte IV is decoded and expanded into its full original 64 bit
form based on the most recently accepted IV.  The IV value is validated to verify that a message with
the same IV has not been received already to avoid replay attacks.  Using this IV and the sender's key,
ChaCha-14 is keyed to generate the first 128-byte block of keystream.  To reject invalid messages more
quickly, the VHash value is recovered before decrypting the message and it is generated by the recipient
for comparison with the decrypted version.  After the VMAC is validated, the message is decrypted in-place.

All algorithms are resilient to side-channel attacks as execution time and cache access times are
independent of secret data.  It seems to also resist power analysis attacks though I haven't checked.

To optimize the ChaCha function for servers and reduce the impact of using strong cryptography, the
[chacha-opt](https://github.com/floodyberry/chacha-opt) implementation is employed when running on
Intel x64 machines.  ChaCha-14 has similar performance to the AES-NI instruction, while being much
faster in software for mobile platforms.

VMAC was chosen over Poly1305 for better speed, portability, and good published analysis [1][2].

The best known attack against ChaCha is on 7 rounds [3][4], so 14 rounds seems like more than enough of
a security margin in trade for exceptional speed.


## References

##### [1] ["VHASH Security" (Dai Krovetz 2007)](https://eprint.iacr.org/2007/338.pdf)
Security analysis of VHASH, the core algorithm of the MAC used by Calico.

##### [2] ["Key-Recovery Attacks on Universal Hash Function based MAC Algorithms" (Handschuh Preneel 2008)](http://www.iacr.org/archive/crypto2008/51570145/51570145.pdf)
Further security analysis of VHASH and other universal hash functions, exploring classes of weak keys and other failures.

##### [3] ["New Features of Latin Dances: Analysis of Salsa, ChaCha, and Rumba" (Aumasson et al 2008)](https://eprint.iacr.org/2007/472.pdf)
Cryptoanalysis of the ChaCha cipher used in Calico.

##### [4] ["Latin Dances Revisited: New Analytic Results of Salsa20 and ChaCha" (Ishiguro 2012)](https://eprint.iacr.org/2012/065.pdf)
Updated analysis of ChaCha security.


## Credits

This software was written entirely by myself ( Christopher A. Taylor <mrcatid@gmail.com> ).  If you
find it useful and would like to buy me a coffee, consider [tipping](https://www.gittip.com/catid/).

Thanks to Sam Hughes ( sam@rethinkdb.com ) for fixing an integer overflow vulnerability in an
early version of the software.
