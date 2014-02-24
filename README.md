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
a similar construction Langley's proposal [4] for using ChaCha20 with Poly1305
for AEAD in TLS.  The main difference is that the simpler SipHash-2-4 MAC [5] is
used for higher speed in place of Poly1305.

Calico does not provide key agreement.  See the [Tabby](https://github.com/catid/tabby)
library for an efficient and portable implementation of key agreement.  Calico
also does not open any sockets for you - It only encodes and decodes the data.
Calico does not consume any randomness to operate.


## Benchmarks

##### libcalico.a on Macbook Air (1.7 GHz Core i5-2557M Sandy Bridge, July 2011):

Output of `make test`:

~~~
Running test 5 : Benchmark Initialize()
Benchmark: Initialize() in 0.49264 usec on average / 2.02988e+06 per second
+++ Test passed.

Running test 6 : Benchmark Encrypt()
calico_datagram_encrypt: 10000 bytes in 8.30996 usec on average / 1203.38 MBPS / 120338 per second
calico_datagram_encrypt: 1000 bytes in 1.11836 usec on average / 894.166 MBPS / 894166 per second
calico_datagram_encrypt: 100 bytes in 0.24781 usec on average / 403.535 MBPS / 4.03535e+06 per second
calico_datagram_encrypt: 10 bytes in 0.11381 usec on average / 87.8657 MBPS / 8.78657e+06 per second
calico_datagram_encrypt: 1 bytes in 0.11607 usec on average / 8.61549 MBPS / 8.61549e+06 per second
+++ Test passed.

Running test 7 : Benchmark Decrypt() Rejection
calico_datagram_decrypt: drops 10000 corrupted bytes in 10.4301 usec on average / 958.76 MBPS / 95876 per second
calico_datagram_decrypt: drops 1000 corrupted bytes in 1.03877 usec on average / 962.677 MBPS / 962677 per second
calico_datagram_decrypt: drops 100 corrupted bytes in 0.12755 usec on average / 784.006 MBPS / 7.84006e+06 per second
calico_datagram_decrypt: drops 10 corrupted bytes in 0.04788 usec on average / 208.855 MBPS / 2.08855e+07 per second
calico_datagram_decrypt: drops 1 corrupted bytes in 0.04111 usec on average / 24.325 MBPS / 2.4325e+07 per second
+++ Test passed.

Running test 8 : Benchmark Decrypt() Accept
calico_datagram_decrypt: 10000 bytes in 19.0175 usec on average / 525.833 MBPS / 52583.3 per second
calico_datagram_decrypt: 1000 bytes in 2.3343 usec on average / 428.394 MBPS / 428394 per second
calico_datagram_decrypt: 100 bytes in 0.56173 usec on average / 178.021 MBPS / 1.78021e+06 per second
calico_datagram_decrypt: 10 bytes in 0.27152 usec on average / 36.8297 MBPS / 3.68297e+06 per second
calico_datagram_decrypt: 1 bytes in 0.25803 usec on average / 3.87552 MBPS / 3.87552e+06 per second
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
desktops, although it will tend to run about 2x slower.


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
libcat/SipHash.*

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
IV takes 3 bytes.  The overhead for the MAC tag takes 8 bytes.  So overall datagram mode
overhead is 11 bytes.

In stream mode, intended for TCP transport, there is no need to explicitly send the IV
used for each message as this can be inferred implicitly by the order in which the data
is received.  3 bytes are saved and only the MAC tag is transmitted as overhead.
So overall stream mode overhead is 8 bytes.

To save roughly 150 bytes, the stream mode can be selected exclusively by using the
`calico_key_stream_only` function.  In this mode the Calico state object does not include
memory for the datagram IVs nor does it include memory for the bit vector used to avoid
replay attacks.

#### Encryption

When a user calls `calico_datagram_encrypt` to encrypt a message, it reads the next IV to
send and verifies that it is not out of IVs to use.  It then encrypts the plaintext of
the message with ChaCha14 and the local datagram key.  A SipHash-2-4 MAC tag is generated
for the encrypted ciphertext of the message.  The IV and tag are stored in the overhead
for the message.  Then the message and its overhead are transmitted to the remote user.

Each IV starts at 0 and is incremented by 1 for each message that is sent using that IV.

The IV is truncated to its 3 low bytes (24 bits) and is obfuscated to make the overhead
look more random.  The obfuscation used is to first subtract off the MAC tag from it, and
then XOR the 24-bit value 0x286AD7.

The IV must be included in the MAC tag, or else it would be trivially possible to replay
an encrypted message for a previous IV.  To efficiently incorporate the IV, it is XOR'd
into the low 8 bytes of the MAC key.  The resulting combined key is then used as usual.

#### Decryption

Message decryption and authentication is performed by `calico_datagram_decrypt`.
It reads the 24-bit truncated IV from the overhead and uses the last accepted IV to
expand it back to the full 64-bit IV value.  The IV is checked to make sure it was not
previous accepted, to avoid replay attacks.  Using the IV and remote datagram key it
initializes the ChaCha cipher.  The SipHash MAC tag for the encrypted message is
recalculated and it is compared to the provided one in the overhead of the message
in constant-time.  If the MAC tag does not match, then the message is rejected.
The message is then decrypted.  And the IV is marked as having been accepted.


## Discussion

The project goals are (in order):

+ Avoiding Timing Side-Channels
+ Avoiding Freed Memory Side-Channels
+ Simplicity
+ Speed
+ Low Overhead
+ Low Memory Size of per-Connection State

Calico attempts to use existing, trusted primitives in efficient and simple combination
to avoid misusing or introducing new buggy code.

The main primitives, ChaCha and SipHash, are trusted and well-analyzed and moreover
do not have timing side-channels and make little use of state so it is easy to erase.
These functions are also simple, though I have chosen to use existing implementations
rather than writing much code of my own.

Care is taken to avoid leaking important information by leaving it on the stack or
in memory somewhere to be read later.

All input parameters are validated to avoid misuse.

All algorithms are resilient to side-channel attacks as execution time and cache access
times are independent of secret data.  It seems to also resist Power Analysis (PA) attacks
though I haven't checked.

#### Setup

An alternative initial state would be a random number for each IV.  This would
not help meaningfully with security because the keys are already large enough.
An older version of the software used this approach.  The advantage of starting
with 0 is that it will never roll over and the code can easily check for IVs that
are about to reach 2^64 to avoid re-using IVs.

The IVs are truncated during encryption to 24 bits, which is tuned for expected
file transfer data rates up to 10 GB/s.  Truncating to 16 bits would allow for
up to 45 MB/s data rates, which did not seem to be future-proof enough for me.

#### Encryption: Importance of AEAD

This is an AEAD scheme.  The MAC is the "Authenticated" part, represented as the 8-byte
tag on each message.  The cipher is the "Encryption" part, which manifests itself in the
ciphertext of the message.  And the "Additional Data" is the IV for the message.

Note that some people define AEAD as only applying to block ciphers, and I am using this
term in a broader sense.

The trickiest part of the encryption in the AEAD construction is how the MAC is applied.

If the IV does not affect the MAC, then it is easy to replay past messages by reusing an
old MAC and associated encrypted data with an unused IV.  The approach taken by Calico
to incorporate the IV efficiently into the MAC is by XORing the IV into the low bits of
the key, so that each message is given a MAC tag based on a slightly different key.
This avoids the replay attack vulnerability and uses no extra CPU time.

#### Encryption: Choice of ChaCha Rounds

To achieve low overhead, the ChaCha14 stream cipher was chosen for use in Calico.
The choice of this stream cipher was motivated by the lack of padding for lower overhead
and the speed of the ChaCha stream cipher.

The stream cipher chosen for encryption is the ChaCha cipher, which has a selectable
number of rounds.  The number of rounds is commonly post-fixed to the name of the cipher
as in "ChaCha8" is an 8-round version of the ChaCha cipher.

To optimize the ChaCha function for servers and reduce the impact of using strong
cryptography, the [chacha-opt](https://github.com/floodyberry/chacha-opt) implementation
is employed when running on Intel x64 machines.  ChaCha14 has similar performance to the
AES-NI instruction, while being much faster in software for mobile platforms.

To aid in deciding the number of rounds to use:  In [1] and [2], it is shown that
ChaCha8 does not provide 256-bit security.  And in [3] a proof for security against
differential cryptoanalysis is given for ChaCha15.

It seems then that a comfortable margin of security is provided by ChaCha14, which offers
30% faster execution time as compared to the full 20-round version.

#### Decryption

During decryption a 1024-bit window is used to keep track of accepted IVs.  This value
was chosen because it is the IPsec largest window allowed.  But it may be worth looking
into expanding this window for high-speed transfers in the future.

#### SipHash-2-4 versus Poly1305 versus VMAC

Choosing which MAC algorithm to use turned out to be one of the more difficult challenges
of putting together Calico.  The metrics to measure performance of a MAC function
(assuming similar security guarantees) are: Long-message performance, short-message
performance, code simplicity, and size of the per-connection state object in memory.

Long-message performance: Dropping a 1000-byte corrupted message on my laptop.

+ VMAC-ChaCha14 : 3179.04 MB/s
+ Poly1305-ChaCha14 : 1000 MB/s
+ SipHash-2-4 : 962.677 MB/s

Short-message performance: Dropping a 100-byte corrupted message on my laptop.

+ SipHash-2-4 : 784.006 MB/s
+ VMAC-ChaCha14 : 514.483 MB/s
+ Poly1305-ChaCha14 : 327.729 MB/s

VMAC is the fastest for long messages but is slower for medium and short messages.
VMAC also has good security analysis and several implementations.  The downsides are
that it requires several hundred bytes of extra memory per connection, and it is much
more complicated than SipHash-2-4/Poly1305.  I was not willing to maintain my VMAC code
and decided to go with the simpler SipHash-2-4/Poly1305 approach.

While SipHash-2-4 is slightly slower for file transfer-sized packets, it is much much
faster for all other types of data than Poly1305-ChaCha14.  And SipHash-2-4 is extremely
simple in code, making it easier to audit than Poly1305.

Poly1305-ChaCha14 requires less state per user in that it consumes the first block of
ChaCha during encryption rather than depending on a 128-bit key like SipHash.  However
this requires an extra execution of the ChaCha function, which slows down Poly1305,
leading to slower short-message performance.

After weighing all three options over several months, SipHash-2-4 was selected as the
MAC for Calico.


## References

##### [1] ["New Features of Latin Dances: Analysis of Salsa, ChaCha, and Rumba" (Aumasson et al 2008)](https://eprint.iacr.org/2007/472.pdf)
Cryptoanalysis of the ChaCha stream cipher used in Calico.

##### [2] ["Latin Dances Revisited: New Analytic Results of Salsa20 and ChaCha" (Ishiguro 2012)](https://eprint.iacr.org/2012/065.pdf)
Updated analysis of ChaCha security.

##### [3] ["Towards Finding Optimal Differential Characteristics for ARX" (Mouha Preneel 2013)](http://eprint.iacr.org/2013/328.pdf)
A proof for security against differential cryptoanalysis is given for ChaCha-15.

##### [4] ["ChaCha20 and Poly1305 based Cipher Suites for TLS" (Langley 2013)](https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-01)
The accepted IETF proposal for incorporating ChaCha and Poly1305 for TLS.

##### [5] ["SipHash: a fast short-input PRF" (Aumasson Bernstein 2013)](https://131002.net/siphash/)
Cryptoanalysis of the SipHash-2-4 MAC used in Calico.


## Credits

This software was written entirely by myself ( Christopher A. Taylor <mrcatid@gmail.com> ).  If you
find it useful and would like to buy me a coffee, consider [tipping](https://www.gittip.com/catid/).

Thanks to Sam Hughes ( sam@rethinkdb.com ) for fixing an integer overflow vulnerability in an
early version of the software.

