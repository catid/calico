/*
	Copyright (c) 2012-2014 Christopher A. Taylor.  All rights reserved.

	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions are met:

	* Redistributions of source code must retain the above copyright notice,
	  this list of conditions and the following disclaimer.
	* Redistributions in binary form must reproduce the above copyright notice,
	  this list of conditions and the following disclaimer in the documentation
	  and/or other materials provided with the distribution.
	* Neither the name of Calico nor the names of its contributors may be used
	  to endorse or promote products derived from this software without
	  specific prior written permission.

	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
	AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
	IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
	ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
	LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
	CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
	SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
	INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
	CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
	ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
	POSSIBILITY OF SUCH DAMAGE.
*/

#include "calico.h"

#include "AuthEnc.hpp"
#include "AntiReplayWindow.hpp"
#include "EndianNeutral.hpp"
#include "SecureErase.hpp"
#include "BitMath.hpp"
using namespace cat;

#include <climits>

/*
 * The user is responsible for how the Calico output is transported to a remote
 * host for decryption.  It is flexible in that the overhead can be stored in
 * any way the user desires.  Encrypted data is the same length as decrypted
 * data and can be encrypted in-place.
 *
 * The overhead format:
 *
 * | <-- earlier bytes  later bytes ->|
 * (00 01 02) (03 04 05 06 07 08 09 0a)
 *     AD            MAC tag
 *
 * AD (Associated Data) (3 bytes):
 *	R = Rekey ratchet flag bit (1 bit), stored in the high bit of byte 02.
 *	IV = Truncated IV (low 23 bits)
 * MAC (Message Authenticate Code) tag (8 bytes):
 * 	Tag that authenticates both the encrypted message and the associated data.
 */

/*
 * Both the initiator and the responder keep two copies of the remote keys.
 * There are two encryption keys: ChaCha (256 bits) and MAC (128 bits).  To be
 * clear, these are treated as one long 48 byte key and are updated together.
 * The key corresponding to R = 0 is the initial encryption key for the remote
 * host (Kr).  The key corresponding to R = 1 is H(Kr).
 *
 * The initiator and responder can each ratchet its encryption key.
 * The initiator will periodically request a ratchet of the private keys.  This
 * is done by flipping the R bit in the associated data of the message stored
 * in the overhead, as shown above.
 *
 * When the responder sees an R bit flip, it will immediately ratchet its key
 * by running K' = H(K), where H = BLAKE2 and K = the local encryption key.
 * Any future outgoing encrypted messages will use the new key K'.  Note that
 * this erases the previous key K and replaces it with K'.  This costs over
 * 2^128 hash operations to run the ratchet backwards, so the security of the
 * scheme is maintained: Previous outgoing messages can no longer be
 * decrypted if the responder is compromised, providing forward secrecy.
 *
 * The initiator and responder both use the keys indicated by R when new
 * datagrams arrive to authenticate and decrypt.  When the remote host sends a
 * valid datagram for ~R, then the receiver starts a timer counting down to
 * updating the R key with K[R] = H(K[~R]).  The timer is initially set to X
 * seconds.  The timer is reset if a valid datagram for R is received.  This
 * prevents the ratchet from losing data when it arrives out of order.
 *
 * The client will ratchet no more often than 2X seconds, where X is roughly
 * 1 minute.
 *
 * TODO: Should both sides be responsible for triggering ratchets?
 */

// IV constants
static const int IV_BYTES = 3;
static const int IV_BITS = IV_BYTES * 8;
static const u32 IV_MSB = (1 << IV_BITS);
static const u32 IV_MASK = (IV_MSB - 1);
static const u32 IV_FUZZ = 0x286AD7;

typedef struct {
	// Encryption and MAC key for outgoing data
	char outgoing[48];

	// Current and next encryption keys for incoming data
	char incoming[2][48];

	// This is either 0 or 1 to indicate which of the two incoming
	// keys is active
	u32 active_incoming;

	// This is the millisecond timestamp when ratcheting started
	// Otherwise it is set to 0 when ratcheting is not in progress
	u32 base_ratchet_time;
} Keys;

// Constants to indicate the Calico state object is keyed
static const u32 FLAG_KEYED_STREAM = 0x6501ccef;
static const u32 FLAG_KEYED_DATAGRAM = 0x6501ccfe;

typedef struct {
	// Flag indicating whether or not the Calico state object is keyed or not
	u32 flag;

	// Encryption and MAC keys for stream mode
	Keys stream;

	// Next IV to use for outgoing stream messages
	u64 stream_outgoing_iv;

	// Next IV to expect for incoming stream messages
	u64 stream_incoming_iv;

	// Extended version for datagrams:

	// Encryption and MAC keys for datagram mode
	Keys datagram;

	// Datagram next IV to send
	u64 datagram_outgoing_iv;

	// Anti-replay window for incoming datagram IVs
	antireplay_state window;
} calico_internal_state;

// Flag to indicate that the library has been initialized with calico_init()
static bool m_initialized = false;


#ifdef __cplusplus
extern "C" {
#endif

int _calico_init(int expected_version)
{
	// If version does not match,
	if (CALICO_VERSION != expected_version) {
		return -1;
	}

	// If internal state is larger than opaque object,
	if (sizeof(calico_internal_state) > sizeof(calico_state)) {
		return -1;
	}
	if (sizeof(calico_internal_state) - sizeof(antireplay_state) > sizeof(calico_stream_only)) {
		return -1;
	}

	m_initialized = true;

	return 0;
}

int calico_key(calico_state *S, int role, const void *key, int key_bytes)
{
	calico_internal_state *state = (calico_internal_state *)S;

	// If input is invalid,
	if (!m_initialized || !key || !state || key_bytes != 32) {
		return -1;
	}

	// If role is invalid,
	if (role != CALICO_INITIATOR && role != CALICO_RESPONDER) {
		return -1;
	}

	// Set flag to unkeyed
	state->flag = 0;

	static const int KEY_BYTES = sizeof(auth_enc_state);
	char keys[KEY_BYTES + KEY_BYTES];

	// Expand key into two keys
	if (!auth_key_expand((const char *)key, keys, sizeof(keys))) {
		return -1;
	}

	// Swap keys based on mode
	char *lkey = keys, *rkey = keys;
	if (role == CALICO_INITIATOR) lkey += KEY_BYTES;
	else rkey += KEY_BYTES;

	// Copy keys into place
	memcpy(&state->local, lkey, sizeof(auth_enc_state));
	memcpy(&state->remote, rkey, sizeof(auth_enc_state));

	// Initialize the IV subsystem for streams
	state->stream_local = 0;
	state->stream_remote = 0;

	// Initialize the IV subsystem for datagrams
	antireplay_init(&state->window);

	// Erase temporary keys from memory
	CAT_SECURE_OBJCLR(keys);

	// Flag as keyed
	state->flag = FLAG_KEYED_DATAGRAM;

	return 0;
}

// Stream-only version
int calico_key_stream_only(calico_stream_only *S, int role,
						   const void *key, int key_bytes)
{
	calico_internal_state *state = (calico_internal_state *)S;

	// If input is invalid,
	if (!m_initialized || !key || !state || key_bytes != 32) {
		return -1;
	}

	// If role is invalid,
	if (role != CALICO_INITIATOR && role != CALICO_RESPONDER) {
		return -1;
	}

	// Set flag to unkeyed
	state->flag = 0;

	static const int KEY_BYTES = sizeof(auth_enc_state);
	char keys[KEY_BYTES + KEY_BYTES];

	// Expand key into two keys
	if (!auth_key_expand((const char *)key, keys, sizeof(keys))) {
		return -1;
	}

	// Swap keys based on mode
	char *lkey = keys, *rkey = keys;
	if (role == CALICO_INITIATOR) lkey += KEY_BYTES;
	else rkey += KEY_BYTES;

	// Copy keys into place
	memcpy(&state->local, lkey, sizeof(auth_enc_state));
	memcpy(&state->remote, rkey, sizeof(auth_enc_state));

	// Initialize the IV subsystem for streams
	state->stream_local = 0;
	state->stream_remote = 0;

	// Erase temporary keys from memory
	CAT_SECURE_OBJCLR(keys);

	// Flag as keyed
	state->flag = FLAG_KEYED_STREAM;

	return 0;
}

int calico_datagram_encrypt(calico_state *S, void *ciphertext, const void *plaintext,
							int bytes, void *overhead)
{
	calico_internal_state *state = (calico_internal_state *)S;

	// If input is invalid or Calico is not keyed,
	if (!m_initialized || !state || !plaintext || !ciphertext ||
		bytes < 0 || !overhead || state->flag != FLAG_KEYED_DATAGRAM) {
		return -1;
	}

	// Get next IV
	const u64 iv = state->window.datagram_local;

	// If out of IVs,
	if (iv == 0xffffffffffffffffULL) {
		return -1;
	}

	// Increment IV
	state->window.datagram_local = iv + 1;

	// Encrypt and generate MAC tag
	const u64 tag = auth_encrypt(&state->local, state->local.datagram_key, iv, plaintext, ciphertext, bytes);

	// Obfuscate the truncated IV
	u32 trunc_iv = (u32)iv;
	trunc_iv -= (u32)tag;
	trunc_iv ^= IV_FUZZ;

	u8 *overhead_iv = reinterpret_cast<u8 *>( overhead );
	u64 *overhead_tag = reinterpret_cast<u64 *>( overhead_iv + 3 );

	// Store IV and tag
	overhead_iv[0] = (u8)trunc_iv;
	overhead_iv[1] = (u8)(trunc_iv >> 16);
	overhead_iv[2] = (u8)(trunc_iv >> 8);

	*overhead_tag = getLE(tag);

	return 0;
}

int calico_datagram_decrypt(calico_state *S, void *ciphertext, int bytes,
							const void *overhead)
{
	calico_internal_state *state = (calico_internal_state *)S;

	// If input is invalid or Calico object is not keyed,
	if (!m_initialized || !state || !ciphertext || !overhead ||
		bytes < 0 || state->flag != FLAG_KEYED_DATAGRAM) {
		return -1;
	}

	const u8 *overhead_iv = reinterpret_cast<const u8 *>( overhead );
	const u64 *overhead_mac = reinterpret_cast<const u64 *>( overhead_iv + 3 );

	// Grab the MAC tag
	const u64 tag = getLE(*overhead_mac);

	// Grab the obfuscated IV
	u32 trunc_iv = ((u32)overhead_iv[2] << 8) | ((u32)overhead_iv[1] << 16) | (u32)overhead_iv[0];

	// De-obfuscate the truncated IV
	trunc_iv ^= IV_FUZZ;
	trunc_iv += (u32)tag;
	trunc_iv &= IV_MASK;

	// Reconstruct the full IV counter
	const u64 iv = ReconstructCounter<IV_BITS>(state->window.datagram_remote, trunc_iv);

	// Validate IV
	if (!antireplay_check(&state->window, iv)) {
		return -1;
	}

	// Decrypt and check MAC
	if (!auth_decrypt(&state->remote, state->remote.datagram_key, iv, ciphertext, bytes, tag)) {
		return -1;
	}

	// Accept this IV
	antireplay_accept(&state->window, iv);

	return 0;
}

int calico_stream_encrypt(void *S, void *ciphertext, const void *plaintext,
						  int bytes, void *overhead)
{
	calico_internal_state *state = (calico_internal_state *)S;

	// If input is invalid or Calico is not keyed,
	if (!m_initialized || !state || !plaintext || !ciphertext || bytes < 0 || !overhead ||
		(state->flag != FLAG_KEYED_STREAM && state->flag != FLAG_KEYED_DATAGRAM)) {
		return -1;
	}

	// Get next IV
	const u64 iv = state->stream_local;

	// If out of IVs,
	if (iv == 0xffffffffffffffffULL) {
		return -1;
	}

	// Increment IV
	state->stream_local = iv + 1;

	// Encrypt and generate MAC tag
	const u64 tag = auth_encrypt(&state->local, state->local.stream_key, iv, plaintext, ciphertext, bytes);

	u64 *overhead_tag = reinterpret_cast<u64 *>( overhead );

	// Write MAC tag
	*overhead_tag = getLE(tag);

	return 0;
}

int calico_stream_decrypt(void *S, void *ciphertext, int bytes, const void *overhead)
{
	calico_internal_state *state = (calico_internal_state *)S;

	// If input is invalid or Calico object is not keyed,
	if (!m_initialized || !state || !ciphertext || !overhead || bytes < 0 ||
		(state->flag != FLAG_KEYED_STREAM && state->flag != FLAG_KEYED_DATAGRAM)) {
		return -1;
	}

	// Get next expected IV
	u64 iv = state->stream_remote;

	// Read MAC tag
	const u64 *overhead_tag = reinterpret_cast<const u64 *>( overhead );
	const u64 tag = getLE(*overhead_tag);

	// Decrypt and check MAC
	if (!auth_decrypt(&state->remote, state->remote.stream_key, iv, ciphertext, bytes, tag)) {
		return -1;
	}

	// Advance IV on success
	state->stream_remote = iv + 1;

	return 0;
}

void calico_cleanup(void *S)
{
	calico_internal_state *state = (calico_internal_state *)S;

	if (state) {
		if (state->flag == FLAG_KEYED_STREAM) {
			cat_secure_erase(S, sizeof(calico_stream_only));
		} else if (state->flag == FLAG_KEYED_DATAGRAM) {
			cat_secure_erase(S, sizeof(calico_state));
		}
	}
}

#ifdef __cplusplus
}
#endif

