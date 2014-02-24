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
rejects invalid messages as quickly as possible -- roughly 2x faster than
normal decryption.

Calico implements Authenticated Encryption with Associated Data (AEAD) using
a similar construction Langley's proposal for using ChaCha20 with Poly1305 for
TLS [4].

Calico does not provide key agreement.  See the [Tabby](https://github.com/catid/tabby)
library for an efficient and portable implementation of key agreement.  Calico
also does not open any sockets for you - It only encodes and decodes the data.
Calico does not consume any randomness to operate.


## Benchmarks

##### libcalico.a on Macbook Air (1.7 GHz Core i5-2557M Sandy Bridge, July 2011):

Output of `make test`:

~~~
Running test 6 : Benchmark Initialize()
Benchmark: Initialize() in 0.61753 usec on average / 1.61935e+06 per second
+++ Test passed.

Running test 7 : Benchmark Encrypt()
Benchmark: Encrypt() 10000 bytes in 9.35767 usec on average / 1068.64 MBPS / 106864 per second
Benchmark: Encrypt() 1000 bytes in 1.24738 usec on average / 801.68 MBPS / 801680 per second
Benchmark: Encrypt() 100 bytes in 0.35006 usec on average / 285.665 MBPS / 2.85665e+06 per second
Benchmark: Encrypt() 10 bytes in 0.20681 usec on average / 48.3536 MBPS / 4.83536e+06 per second
Benchmark: Encrypt() 1 bytes in 0.17159 usec on average / 5.82785 MBPS / 5.82785e+06 per second
+++ Test passed.

Running test 8 : Benchmark Decrypt() Rejection
Benchmark: Decrypt() drops 10000 corrupted bytes in 1.77144 usec on average / 5645.12 MBPS / 564512 per second
Benchmark: Decrypt() drops 1000 corrupted bytes in 0.31456 usec on average / 3179.04 MBPS / 3.17904e+06 per second
Benchmark: Decrypt() drops 100 corrupted bytes in 0.19437 usec on average / 514.483 MBPS / 5.14483e+06 per second
Benchmark: Decrypt() drops 10 corrupted bytes in 0.19448 usec on average / 51.4192 MBPS / 5.14192e+06 per second
Benchmark: Decrypt() drops 1 corrupted bytes in 0.17031 usec on average / 5.87165 MBPS / 5.87165e+06 per second
+++ Test passed.

Running test 9 : Benchmark Decrypt() Accept
Benchmark: Decrypt() 10000 bytes in 9.4023 usec on average / 1063.57 MBPS / 106357 per second
Benchmark: Decrypt() 1000 bytes in 1.35572 usec on average / 737.615 MBPS / 737615 per second
Benchmark: Decrypt() 100 bytes in 0.44144 usec on average / 226.531 MBPS / 2.26531e+06 per second
Benchmark: Decrypt() 10 bytes in 0.26523 usec on average / 37.7031 MBPS / 3.77031e+06 per second
Benchmark: Decrypt() 1 bytes in 0.28565 usec on average / 3.50079 MBPS / 3.50079e+06 per second
+++ Test passed.
~~~

When over 1000 messages can be encrypted/decrypted in under a millisecond, encryption should not
be a bottleneck for any network application.

These tests were also re-run with valgrind, which took a lot longer. =)


## Usage

#### Example Usage

For example usage, check out the [example test](https://github.com/catid/calico/blob/master/tests/calico_example.cpp).

For more thorough usage, check out the [unit tester code](https://github.com/catid/calico/blob/master/tests/calico_test.cpp).


#### Building: Quick Setup

The [calico-mobile](https://github.com/catid/calico/tree/master/calico-mobile)
directory contains an easy-to-import set to C code that
also builds properly for mobile devices.  In a pinch you can use this code for
desktops, although it will tend to run about 2.5x slower.


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

#### Setup

The single 32 byte key provided to `calico_key` is expanded into two encryption keys for
stream-mode output, and two encryption keys for datagram-mode output.  Each user decides
which of the keys to use, based on their role: `CALICO_INITIATOR` or `CALICO_RESPONDER`.

The remote-expected and next-local IV for datagram/stream modes are set to 0.

#### Modes

The user can choose to encrypt either in "stream" or "datagram" mode.  These modes
correspond to different keys and different next-local IVs.

In datagram mode, the overhead added by encryption includes the Message Authentication
Code (MAC) tag, and the unique IV corresponding to the message.  The IVs are incremented
by one each time to ensure they are unique and to simplify the code.  The overhead for
IV takes 3 bytes, tuned for expected file transfer data rates up to 10 GB/s.  The overhead
for the MAC tag takes 8 bytes.  So overall datagram mode overhead is 11 bytes.

In stream mode, intended for TCP transport, there is no need to explicitly send the IV
used for each message as this can be inferred implicitly by the order in which the data
is received.  3 bytes are saved and only the MAC tag is transmitted as overhead.
So overall stream mode overhead is 8 bytes.

To save roughly 150 bytes, the stream mode can be selected exclusively by using the
`calico_key_stream_only` function.  In this mode the Calico state object does not include
memory for the datagram IVs nor does it include memory for the bit vector used to avoid
replay attacks.

#### Encryption

Calico uses the ChaCha14 cipher.



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


## Discussion

The project goals are (in order):

+ Avoiding Timing Side-Channels
+ Avoiding Freed Memory Side-Channels
+ Simplicity
+ Speed
+ Low Overhead

Calico attempts to use existing, trusted primitives in efficient and simple combination
to avoid misusing or introducing new buggy code.

The main primitives, ChaCha and Poly1305, are trusted and well-analyzed and moreover
do not have timing side-channels and make little use of state so it is easy to erase.
These functions are also simple, though I have chosen to use existing implementations
rather than writing much code of my own.

Care is taken to avoid leaking important information by leaving it on the stack or
in memory somewhere to be read later.

#### Setup

An alternative initial state would be a random number for each IV.  This would
not help meaningfully with security because the keys are already large enough.
The advantage of starting with 0 is that it will never roll over and the code
can easily check for IVs that are about to reach 2^64 to avoid re-using IVs.

#### Encryption

The cipher chosen for encryption is the ChaCha cipher, which has a selectable number of
rounds.  The number of rounds is commonly post-fixed to the name of the cipher as in
"ChaCha8" is an 8-round version of the ChaCha cipher.

In [1], it is shown that ChaCha8 does not provide 256-bit security.  And in [2] a
proof for security against differential cryptoanalysis is given for ChaCha15.

It seems then that a comfortable margin of security is provided by ChaCha14, which offers
30% faster execution time as compared to the full 20-round version.

#### VMAC versus SipHash

Note there is also a branch of Calico (called "siphash") that uses SipHash-2-4.  It works, and I
was hoping to switch to SipHash since it's much simpler.  However, SipHash is significantly
slower than VMAC.

These are the results on my laptop from SipHash:

~~~
Benchmark: Decrypt() 10000 bytes in 16.8788 usec on average / 592.457 MBPS / 59245.7 per second
Benchmark: Decrypt() 1000 bytes in 2.07803 usec on average / 481.225 MBPS / 481225 per second
Benchmark: Decrypt() 100 bytes in 0.4967 usec on average / 201.329 MBPS / 2.01329e+06 per second
Benchmark: Decrypt() 10 bytes in 0.24967 usec on average / 40.0529 MBPS / 4.00529e+06 per second
Benchmark: Decrypt() 1 bytes in 0.25605 usec on average / 3.90549 MBPS / 3.90549e+06 per second
~~~

And these are the results from VMAC:

~~~
Benchmark: Decrypt() 10000 bytes in 9.4023 usec on average / 1063.57 MBPS / 106357 per second
Benchmark: Decrypt() 1000 bytes in 1.35572 usec on average / 737.615 MBPS / 737615 per second
Benchmark: Decrypt() 100 bytes in 0.44144 usec on average / 226.531 MBPS / 2.26531e+06 per second
Benchmark: Decrypt() 10 bytes in 0.26523 usec on average / 37.7031 MBPS / 3.77031e+06 per second
Benchmark: Decrypt() 1 bytes in 0.28565 usec on average / 3.50079 MBPS / 3.50079e+06 per second
~~~

Furthermore the advantage of rejecting messages before full decryption drops from 4x faster to
only 2x faster when using SipHash.  For file transfer sizes > 1000 bytes, the VMAC implementation
is getting close to twice as fast as the one based on SipHash.  And for very small messages they
are so close in performance it hardly matters.

If the performance was somewhat close I would accept lower performance for a cleaner codebase,
but there is too big a gap in my opinion.


## References

##### [1] ["New Features of Latin Dances: Analysis of Salsa, ChaCha, and Rumba" (Aumasson et al 2008)](https://eprint.iacr.org/2007/472.pdf)
Cryptoanalysis of the ChaCha cipher used in Calico.

##### [2] ["Latin Dances Revisited: New Analytic Results of Salsa20 and ChaCha" (Ishiguro 2012)](https://eprint.iacr.org/2012/065.pdf)
Updated analysis of ChaCha security.

##### [3] ["Towards Finding Optimal Differential Characteristics for ARX" (Mouha Preneel 2013)](http://eprint.iacr.org/2013/328.pdf)
A proof for security against differential cryptoanalysis is given for ChaCha-15.

##### [4] ["ChaCha20 and Poly1305 based Cipher Suites for TLS" (Langley 2013)](https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-01)
The accepted IETF proposal for incorporating ChaCha and Poly1305 for TLS.


## Credits

This software was written entirely by myself ( Christopher A. Taylor <mrcatid@gmail.com> ).  If you
find it useful and would like to buy me a coffee, consider [tipping](https://www.gittip.com/catid/).

Thanks to Sam Hughes ( sam@rethinkdb.com ) for fixing an integer overflow vulnerability in an
early version of the software.

