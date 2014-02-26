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

// Additional data constants (includes IV and R-bit)
static const int AD_BYTES = 3;
static const int AD_BITS = AD_BYTES * 8;
static const u32 AD_MSB = (1 << AD_BITS);
static const u32 AD_MASK = (AD_MSB - 1);
static const u32 AD_FUZZ = 0xC86AD7;

// IV constants
static const int IV_BITS = 23;

// Number of bytes in the keys for one transmitter
// Includes 32 bytes for the encryption key
// and 16 bytes for the MAC key
static const int KEY_BYTES = 32 + 16;

struct Keys {
	// Encryption and MAC key for outgoing data
	char out[KEY_BYTES];

	// Current and next encryption keys for incoming data
	char in[2][KEY_BYTES];

	// This is either 0 or 1 to indicate which of the two incoming
	// keys is "active"; the other key is "inactive" and will be
	// set to H(K_active)
	u32 active_in;

	// This is either 0 or 1 to indicate which of the two outgoing
	// keys in active on the receiver side.  Whenever the local key
	// ratchets this bit flips
	u32 active_out;

	// This is the millisecond timestamp when ratcheting started
	// Otherwise it is set to 0 when ratcheting is not in progress
	u32 base_ratchet_time;
};

// Minimum time between rekeying
static const u32 RATCHET_PERIOD = 60 * 2 * 1000; // 120 seconds in milliseconds

// This is the time after the receiver sees a remote key switch past
// which the receiver will ratchet the remote key to forget the old one
static const u32 RATCHET_REMOTE_TIMEOUT = 60 * 1000; // 60 seconds in milliseconds

// Constants to indicate the Calico state object is keyed
static const u32 FLAG_KEYED_STREAM = 0x6501ccef;
static const u32 FLAG_KEYED_DATAGRAM = 0x6501ccfe;

struct InternalState {
	// Flag indicating whether or not the Calico state object is keyed or not
	u32 flag;

	// Encryption and MAC keys for stream mode
	Keys stream;

	// Next IV to use for outgoing stream messages
	u64 stream_out_iv;

	// Next IV to expect for incoming stream messages
	u64 stream_in_iv;

	// --- Extended version for datagrams: ---

	// Encryption and MAC keys for datagram mode
	Keys dgram;

	// Next IV to use for outgoing datagram messages
	u64 dgram_out_iv;

	// Anti-replay window for incoming datagram IVs
	antireplay_state window;
};

// Flag to indicate that the library has been initialized with calico_init()
static bool m_initialized = false;


// Helper function to ratchet a key
static void ratchet_key(const char key[KEY_BYTES], char next_key[KEY_BYTES]) {
	blake2b_state B;

	// Initialize BLAKE2 for 48 bytes of output (it supports up to 64)
	if (blake2b_init(&B, KEY_BYTES)) {
		return -1;
	}

	// Mix in the previous key
	if (blake2b_update(&B, (const u8 *)key, KEY_BYTES)) {
		return -1;
	}

	// Generate the new key
	if (blake2b_final(&B, (u8 *)next_key, KEY_BYTES)) {
		return -1;
	}

	// Erase temporary workspace
	CAT_SECURE_OBJCLR(B);
}


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
	if (sizeof(InternalState) > sizeof(calico_state)) {
		return -1;
	}
	if (offsetof(InternalState, dgram) > sizeof(calico_stream_only)) {
		return -1;
	}

	m_initialized = true;

	return 0;
}

void calico_cleanup(void *S)
{
	InternalState *state = reinterpret_cast<InternalState *>( S );

	if (state) {
		if (state->flag == FLAG_KEYED_STREAM) {
			cat_secure_erase(S, sizeof(calico_stream_only));
		} else if (state->flag == FLAG_KEYED_DATAGRAM) {
			cat_secure_erase(S, sizeof(calico_state));
		}
	}
}


//// Keying

int calico_key(calico_state *S, int role, const void *key, int key_bytes)
{
	InternalState *state = reinterpret_cast<InternalState *>( S );

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

	// Stream and datagram keys for both sides
	static const int COMBINED_BYTES = KEY_BYTES * 2;
	char keys[COMBINED_BYTES * 2];

	// Expand key into two sets of two keys
	if (!auth_key_expand((const char *)key, keys, sizeof(keys))) {
		return -1;
	}

	// Swap keys based on mode
	char *lkey = keys, *rkey = keys;
	if (role == CALICO_INITIATOR) lkey += COMBINED_BYTES;
	else rkey += COMBINED_BYTES;

	// Copy keys into place
	memcpy(state->stream.out, lkey, KEY_BYTES);
	memcpy(state->datagram.out, lkey + KEY_BYTES, KEY_BYTES);
	memcpy(state->stream.in[0], rkey, KEY_BYTES);
	memcpy(state->datagram.in[0], rkey + KEY_BYTES, KEY_BYTES);

	// Generate the next remote key
	ratchet_key(state->stream.in[0], state->stream.in[1]);
	ratchet_key(state->datagram.in[0], state->datagram.in[1]);

	// Initialize the IV subsystem for streams
	state->stream_out_iv = 0;
	state->stream_in_iv = 0;

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
	InternalState *state = reinterpret_cast<InternalState *>( S );

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

	// Stream keys for both sides
	char keys[KEY_BYTES * 2];

	// Expand key into two sets of two keys
	if (!auth_key_expand((const char *)key, keys, sizeof(keys))) {
		return -1;
	}

	// Swap keys based on mode
	char *lkey = keys, *rkey = keys;
	if (role == CALICO_INITIATOR) lkey += KEY_BYTES;
	else rkey += KEY_BYTES;

	// Copy keys into place
	memcpy(state->stream.out, lkey, KEY_BYTES);
	memcpy(state->stream.in[0], rkey, KEY_BYTES);

	// Generate the next remote key
	ratchet_key(state->stream.in[0], state->stream.in[1]);

	// Initialize the IV subsystem for streams
	state->stream_out_iv = 0;
	state->stream_in_iv = 0;

	// Erase temporary keys from memory
	CAT_SECURE_OBJCLR(keys);

	// Flag as keyed
	state->flag = FLAG_KEYED_STREAM;

	return 0;
}


//// Encryption

int calico_datagram_encrypt(calico_state *S, void *ciphertext, const void *plaintext,
							int bytes, void *overhead)
{
	InternalState *state = reinterpret_cast<InternalState *>( S );

	// If input is invalid or Calico is not keyed,
	if (!m_initialized || !state || !plaintext || !ciphertext ||
		bytes < 0 || !overhead || state->flag != FLAG_KEYED_DATAGRAM) {
		return -1;
	}

	// Get next IV
	const u64 iv = state->dgram_out_iv;

	// If out of IVs,
	if (iv == 0xffffffffffffffffULL) {
		return -1;
	}

	// Increment IV
	state->dgram_out_iv = iv + 1;

	// Encrypt and generate MAC tag
	const u64 tag = auth_encrypt(state->dgram.out, iv, plaintext, ciphertext, bytes);

	// Obfuscate the truncated IV
	u32 trunc_iv = ((u32)iv << 1) | state->dgram.active_out;
	trunc_iv -= (u32)tag;
	trunc_iv ^= AD_FUZZ;

	u8 *overhead_iv = reinterpret_cast<u8 *>( overhead );
	u64 *overhead_tag = reinterpret_cast<u64 *>( overhead_iv + 3 );

	// Store IV and tag
	overhead_iv[0] = (u8)trunc_iv;
	overhead_iv[1] = (u8)(trunc_iv >> 16);
	overhead_iv[2] = (u8)(trunc_iv >> 8);

	*overhead_tag = getLE(tag);

	return 0;
}

// Stream version
int calico_stream_encrypt(void *S, void *ciphertext, const void *plaintext,
						  int bytes, void *overhead)
{
	InternalState *state = reinterpret_cast<InternalState *>( S );

	// If input is invalid or Calico is not keyed,
	if (!m_initialized || !state || !plaintext || !ciphertext || bytes < 0 || !overhead ||
		(state->flag != FLAG_KEYED_STREAM && state->flag != FLAG_KEYED_DATAGRAM)) {
		return -1;
	}

	// Get next IV
	const u64 iv = state->stream_out_iv;

	// If out of IVs,
	if (iv == 0xffffffffffffffffULL) {
		return -1;
	}

	// Increment IV
	state->stream_out_iv = iv + 1;

	// Encrypt and generate MAC tag
	const u64 tag = auth_encrypt(state->stream.out, iv, plaintext, ciphertext, bytes);

	u64 *overhead_tag = reinterpret_cast<u64 *>( overhead );

	// Write MAC tag
	*overhead_tag = getLE(tag);

	return 0;
}


//// Decryption

int calico_datagram_decrypt(calico_state *S, void *ciphertext, int bytes,
							const void *overhead)
{
	InternalState *state = reinterpret_cast<InternalState *>( S );

	// If input is invalid or Calico object is not keyed,
	if (!m_initialized || !state || !ciphertext || !overhead ||
		bytes < 0 || state->flag != FLAG_KEYED_DATAGRAM) {
		return -1;
	}

	// TODO: Check if key ratchet should happen here

	const u8 *overhead_iv = reinterpret_cast<const u8 *>( overhead );
	const u64 *overhead_mac = reinterpret_cast<const u64 *>( overhead_iv + 3 );

	// Grab the MAC tag
	const u64 tag = getLE(*overhead_mac);

	// Grab the obfuscated IV
	u32 trunc_iv = ((u32)overhead_iv[2] << 8) | ((u32)overhead_iv[1] << 16) | (u32)overhead_iv[0];

	// De-obfuscate the truncated IV
	trunc_iv ^= AD_FUZZ;
	trunc_iv += (u32)tag;
	trunc_iv &= AD_MASK;

	// Pull out the ratchet bit
	const u32 ratchet_bit = trunc_iv & 1;
	trunc_iv >>= 1;

	// If the ratchet bit is not the active key,
	if (ratchet_bit ^ state->dgram.active_in) {
		// TODO: Start key ratcheting here if not started yet
	}

	// Reconstruct the full IV counter
	const u64 iv = ReconstructCounter<IV_BITS>(state->dgram.out[ratchet_bit], trunc_iv);

	// Validate IV
	if (!antireplay_check(&state->window, iv)) {
		return -1;
	}

	// Decrypt and check MAC
	if (!auth_decrypt(state->remote.datagram_key, iv, ciphertext, bytes, tag)) {
		return -1;
	}

	// Accept this IV
	antireplay_accept(&state->window, iv);

	return 0;
}

// Stream version
int calico_stream_decrypt(void *S, void *ciphertext, int bytes, const void *overhead)
{
	InternalState *state = reinterpret_cast<InternalState *>( S );

	// TODO: Check if key ratchet should happen here

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

	// Pull out the ratchet bit
	const u32 ratchet_bit = trunc_iv & 1;
	trunc_iv >>= 1;

	// If the ratchet bit is not the active key,
	if (ratchet_bit ^ state->dgram.active_in) {
		// TODO: Start key ratcheting here if not started yet
	}

	// TODO

	// Decrypt and check MAC
	if (!auth_decrypt(state->remote.stream_key, iv, ciphertext, bytes, tag)) {
		return -1;
	}

	// Advance IV on success
	state->stream_remote = iv + 1;

	return 0;
}

#ifdef __cplusplus
}
#endif

