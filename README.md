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

##### libcalico.a on iMac (2.7 GHz Core i5-2500S Sandy Bridge, June 2011):

Output of `make test`:

~~~
Running test 8 : Benchmark Initialize()
Benchmark: Initialize() in 1.14809 usec on average / 871012 per second
+++ Test passed.

Running test 9 : Benchmark Encrypt()
calico_encrypt: 10000 bytes in 15.8626 usec on average / 630.415 MBPS / 63041.5 per second
calico_encrypt: 1000 bytes in 1.81763 usec on average / 550.167 MBPS / 550167 per second
calico_encrypt: 100 bytes in 0.3458 usec on average / 289.184 MBPS / 2.89184e+06 per second
calico_encrypt: 10 bytes in 0.1906 usec on average / 52.4659 MBPS / 5.24659e+06 per second
calico_encrypt: 1 bytes in 0.11954 usec on average / 8.3654 MBPS / 8.3654e+06 per second
+++ Test passed.

Running test 10 : Benchmark Decrypt() Rejection
calico_decrypt: drops 10000 corrupted bytes in 8.82259 usec on average / 1133.45 MBPS / 113345 per second
calico_decrypt: drops 1000 corrupted bytes in 0.89105 usec on average / 1122.27 MBPS / 1.12227e+06 per second
calico_decrypt: drops 100 corrupted bytes in 0.1345 usec on average / 743.494 MBPS / 7.43494e+06 per second
calico_decrypt: drops 10 corrupted bytes in 0.04306 usec on average / 232.234 MBPS / 2.32234e+07 per second
calico_decrypt: drops 1 corrupted bytes in 0.03584 usec on average / 27.9018 MBPS / 2.79018e+07 per second
+++ Test passed.

Running test 11 : Benchmark Decrypt() Accept
calico_decrypt: 10000 bytes in 15.8109 usec on average / 632.475 MBPS / 63247.5 per second
calico_decrypt: 1000 bytes in 1.8493 usec on average / 540.745 MBPS / 540745 per second
calico_decrypt: 100 bytes in 0.48162 usec on average / 207.633 MBPS / 2.07633e+06 per second
calico_decrypt: 10 bytes in 0.24286 usec on average / 41.176 MBPS / 4.1176e+06 per second
calico_decrypt: 1 bytes in 0.22032 usec on average / 4.53885 MBPS / 4.53885e+06 per second
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

blake2/ref/blake2.h
blake2/ref/blake2-impl.h
blake2/ref/blake2-ref.c

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

To save 312 bytes, the stream mode can be selected exclusively by using the
`calico_stream_only` state object.  In this mode the Calico state object does not include
memory for the datagram IVs nor does it include memory for the bit vector used to avoid
replay attacks.

#### Encryption

When a user calls `calico_encrypt` to encrypt a message, it reads the next IV to
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

Message decryption and authentication is performed by `calico_decrypt`.
It reads the 24-bit truncated IV from the overhead and uses the last accepted IV to
expand it back to the full 64-bit IV value.  The IV is checked to make sure it was not
previous accepted, to avoid replay attacks.  Using the IV and remote datagram key it
initializes the ChaCha cipher.  The SipHash MAC tag for the encrypted message is
recalculated and it is compared to the provided one in the overhead of the message
in constant-time.  If the MAC tag does not match, then the message is rejected.
The message is then decrypted.  And the IV is marked as having been accepted.

#### Overhead Format

The user is responsible for how the Calico output is transported to a remote
host for decryption.  It is flexible in that the overhead can be stored in
any way the user desires.  Encrypted data is the same length as decrypted
data and can be encrypted in-place.

The overhead format varies based on whether it is in Stream or Datagram mode.

Datagram mode overhead format:

~~~
	| <-- earlier bytes  later bytes ->|
	(00 01 02 03 04 05 06 07) (08 09 0a)
	         MAC tag            IV | R

	MAC (Message Authenticate Code) tag (8 bytes):
		Tag that authenticates both the encrypted message and the associated data.
	IV | R (3 bytes):
		IV = Truncated IV (high 23 bits)
			The full 64-bit IV is the "additional data".
		R = Rekey ratchet flag bit (1 bit), stored in the least significant bit.
			Used to select the key used.
~~~

Stream mode overhead format:

~~~
	| <--      bytes      ->|
	(00 01 02 03 04 05 06 07)
	        MAC tag | R

	MAC (Message Authenticate Code) tag (63 high bits):
		Tag that authenticates both the encrypted message and the associated data.
	R = Rekey ratchet flag bit (1 low bit), stored in the least significant bit.
		Used to select the key used.
~~~

#### Forward Secrecy through Rekeying

The advantage of the form of rekeying used in this library is that it provides
forward secrecy for long-lived connections, without needing to involve the key
agreement mechanism of the protocol.

This scheme assumes that both sides are sending packets back and forth.  This
rekeying scheme does not work if data is only ever sent but not received back
from the other side, because there is no way to verify that the receiver is
kept in synch.  If encrypted messages are only sent but never received, then
the rekeying will never happen.  This is to avoid causing data loss for UDP+TCP
dual streams where the transmitter sends UDP data infrequently.  To enable
rekeying, have the quiet side transmit an encrypted packet at about the rate
that the rekeying should happen.

Older protocols like TLS used rekeying to strengthen keys on the principle that
keys would get weaker after consistent use.  With 256-bit ciphers this is no
longer an issue.  So the purpose of this rekeying is not to strengthen keys but
to provide forward secrecy.

This system is designed for smooth synchronization that does not lose data.  It
uses just one bit of overhead, stolen from extra bits of the IV field or MAC tag,
so adding rekeying does not have any real disadvantages.

Rekeying happens at most once every 2 minutes.  This is a fixed constant in the
code, which can be adjusted if needed.

For synchronization, the CALICO_INITIATOR starts the rekey process and the
CALICO_RESPONDER will acknowledge the rekeying.  The communication happens via
a single bit called the "Ratchet bit."  See the Overhead Format section above
for where it is located based on Stream/Datagram mode.

For smooth synchronization, both the initiator and the responder keep two
versions of the remote key: The "active" key and the "inactive" key.
The "inactive" key is always a hash of the "active" key.
`K_inactive = H(K_active)`, where `H()` is the BLAKE2 hash function.

The active key flips between locations numbered 0 and 1.  Each time the active
key flips, the old key is erased by the new inactive key, hence forward secrecy.

When an encrypted message is sent, the transmitter can select which of these
keys the receiver must use for decryption by toggling the Ratchet bit in the
message overhead.  At the same time, toggling the Ratchet bit indicates to the
receiver that rekeying has occurred.

Recall that there are two Calico keys: ChaCha (256 bits) and MAC (128 bits).
To be clear, these are treated as one long 48 byte key and are updated together.
On startup the key corresponding to R = 0 is the encryption key for the
remote host (K).  The key corresponding to R = 1 is H(K), where H() is the BLAKE2
hash function.

Debouncing is employed to ensure that when datagram messages arrive out of
order, the receiver does not ratchet the decryption key too fast.  Since both
sides of the communication know that the initiator will not ratchet the key
faster than once every 2 minutes, the receiver will wait 1 minute after a
ratchet bit toggle before erasing the old key and preventing out-of-order
messages from being received.

Note that the ratchet bit is not included in the "Additional Data" that is
authenticated by the MAC tag in each message.  Instead since the ratchet bit
selects which key to use for the MAC, it is also authenticated.

Reactions such as rekeying only happen after the message is authenticated.

Rekeying is the most complex part of Calico, despite that it only involves one
overhead bit.  A short example of the process is provided to help clarify:

##### Rekeying Example

Both initiator and responder are keyed.  Initially the active outgoing keys
for both sides are set to key number 0.  Key number 1 is the inactive key and
is set to `H(K_active)`, where `H()` is the BLAKE2 hash function.  These are
48-byte keys, including the encryption and MAC keys.

After 2 minutes the initiator starts the rekey process by flipping its Ratchet
bit during encryption.  There is only one copy of the encryption key, so as
soon as the Ratchet bit is flipped, the encryption key is replaced by the
BLAKE2 hash of that key.  Old data is now safe from key compromise on the
initiator side after this point.

The responder receives the packet, and it uses the inactive key to authenticate
and decrypt the packet.  After authentication is verified, the responder
immediately ratchets its own encryption key, replacing the key by its hash
and flipping its Ratchet bit.  The responder will start a 1 minute timer to
ratchet its decryption keys, allowing time for out-of-order messages to arrive
from before the key ratcheting.

Some time later the responder will encrypt a packet to send back to the
initiator.  The initiator will authenticate the packet and note that the
responder has ratcheted its key.  The initiator will also start a 1 minute
timer to ratchet its decryption keys.

Encrypted messages are sent by both sides using the ratcheted encryption keys
on each side.

The timer on each side will finish, and each side will ratchet its decryption
keys.  Now the old key is completely erased by both sides.

After about another minute the initiator will rekey again as soon as it notices
that the responder had flipped its Ratchet bit.  This prevents the initiator
from rekeying too fast: The responder's Ratchet bit flip serves as an
acknowledgement to the initiator enabling it to rekey again.


## Discussion

The project goals are (in order):

+ Avoiding Timing Side-Channels (use good algorithms)
+ Avoiding Stale Memory Side-Channels (clean up the stack)
+ Forward Secrecy (rekeying)
+ Simplicity (KISS)
+ Speed
+ Low Overhead (low bandwidth)
+ Low Memory Size of per-Connection State (more connections per server)

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

#### Rekeying

The rekeying method through bit-flagged ratcheting seems to have the one disadvantage
that one-way channels do not benefit from rekeying.  Ensuring that at least one packet
is sent from the quiet side about once every 2 minutes should ensure that rekeying
happens in this case.

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

