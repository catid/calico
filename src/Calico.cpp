/*
	Copyright (c) 2012-2013 Christopher A. Taylor.  All rights reserved.

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

#include <iostream>
using namespace std;

#include "calico.h"

#include "ChaChaVMAC.hpp"
#include "AntiReplayWindow.hpp"
#include "EndianNeutral.hpp"
#include "SecureErase.hpp"
#include "BitMath.hpp"
using namespace cat;

#include <climits>

// IV constants
static const int IV_BYTES = 3;
static const int IV_BITS = IV_BYTES * 8;
static const u32 IV_MSB = (1 << IV_BITS);
static const u32 IV_MASK = (IV_MSB - 1);
static const u32 IV_FUZZ = 0x9F286AD7;

typedef struct {
	u32 flag;
	chacha_vmac_state local, remote;
	u64 stream_local, stream_remote;

	// Extended version for datagrams
	antireplay_state window;
} calico_internal_state;

static bool m_initialized = false;
static const u32 FLAG_KEYED_STREAM = 0x6501ccef;
static const u32 FLAG_KEYED_DATAGRAM = 0x6501ccfe;

#ifdef __cplusplus
extern "C" {
#endif

int _calico_init(int expected_version) {
	// If version does not match,
	if (CALICO_VERSION != expected_version) {
		return -1;
	}

	// If internal state is larger than opaque object,
	if (sizeof(calico_internal_state) > sizeof(calico_state)) {
		cout << "TEST: " << sizeof(calico_internal_state) << endl;
		return -1;
	}
	if (sizeof(calico_internal_state) - sizeof(antireplay_state) > sizeof(calico_stream_only)) {
		cout << "TEST: " << (sizeof(calico_internal_state) - sizeof(antireplay_state)) << endl;
		return -1;
	}

	m_initialized = true;

	return 0;
}

int calico_key(calico_state *S, int role, const void *key, int key_bytes) {
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

	// Expand key into two keys using ChaCha20:

	static const int KEY_BYTES = sizeof(chacha_vmac_state) + 32;

	char keys[KEY_BYTES + KEY_BYTES];
	if (!chacha_key_expand((const char *)key, keys, sizeof(keys))) {
		return -1;
	}

	// Swap keys based on mode
	char *lkey = keys, *rkey = keys;
	if (role == CALICO_INITIATOR) lkey += KEY_BYTES;
	else rkey += KEY_BYTES;

	// Set up the ChaCha and VHash keys
	memcpy(&state->local, lkey, sizeof(chacha_vmac_state));
	memcpy(&state->remote, rkey, sizeof(chacha_vmac_state));
	vhash_set_key(&state->local.hash_state);
	vhash_set_key(&state->remote.hash_state);

	// Grab the IVs from the key bytes
	const u64 *local_ivs = reinterpret_cast<const u64 *>( lkey + sizeof(chacha_vmac_state) );
	const u64 *remote_ivs = reinterpret_cast<const u64 *>( rkey + sizeof(chacha_vmac_state) );
	u64 datagram_local = getLE(local_ivs[0]);
	u64 datagram_remote = getLE(remote_ivs[0]);

	// Initialize the IV subsystem for streams
	state->stream_local = getLE(local_ivs[1]);
	state->stream_remote = getLE(remote_ivs[1]);

	// Initialize the IV subsystem for datagrams
	antireplay_init(&state->window, datagram_local, datagram_remote);

	CAT_SECURE_OBJCLR(keys);

	// Flag as keyed
	state->flag = FLAG_KEYED_DATAGRAM;

	return 0;
}

// Stream-only version
int calico_key_stream_only(calico_stream_only *S, int role, const void *key, int key_bytes) {
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

	// Expand key into two keys using ChaCha20:

	static const int KEY_BYTES = sizeof(chacha_vmac_state) + 32;

	char keys[KEY_BYTES + KEY_BYTES];
	if (!chacha_key_expand((const char *)key, keys, sizeof(keys))) {
		return -1;
	}

	// Swap keys based on mode
	char *lkey = keys, *rkey = keys;
	if (role == CALICO_INITIATOR) lkey += KEY_BYTES;
	else rkey += KEY_BYTES;

	// Set up the ChaCha and VHash keys
	memcpy(&state->local, lkey, sizeof(chacha_vmac_state));
	memcpy(&state->remote, rkey, sizeof(chacha_vmac_state));
	vhash_set_key(&state->local.hash_state);
	vhash_set_key(&state->remote.hash_state);

	// Grab the IVs from the key bytes
	const u64 *local_ivs = reinterpret_cast<const u64 *>( lkey + sizeof(chacha_vmac_state) );
	const u64 *remote_ivs = reinterpret_cast<const u64 *>( rkey + sizeof(chacha_vmac_state) );

	// Initialize the IV subsystem for streams
	state->stream_local = getLE(local_ivs[1]);
	state->stream_remote = getLE(remote_ivs[1]);

	CAT_SECURE_OBJCLR(keys);

	// Flag as keyed
	state->flag = FLAG_KEYED_STREAM;

	return 0;
}

int calico_datagram_encrypt(calico_state *S, void *ciphertext, const void *plaintext, int bytes, void *overhead) {
	calico_internal_state *state = (calico_internal_state *)S;

	// If input is invalid or Calico is not keyed,
	if (!m_initialized || !state || !plaintext || !ciphertext ||
		bytes < 0 || !overhead || state->flag != FLAG_KEYED_DATAGRAM) {
		return -1;
	}

	// Select next IV
	const u64 iv = state->window.datagram_local++;

	// Encrypt and generate MAC
	u64 mac = chacha_encrypt(&state->local, state->local.datagram_key, iv, plaintext, ciphertext, bytes, overhead);

	// Obfuscate the truncated IV
	u32 trunc_iv = (u32)iv;
	trunc_iv -= (u32)mac;
	trunc_iv ^= IV_FUZZ;

	u8 *overhead_iv = reinterpret_cast<u8 *>( overhead );
	u64 *overhead_mac = reinterpret_cast<u64 *>( overhead_iv + 3 );

	// Store IV and MAC
	overhead_iv[0] = (u8)trunc_iv;
	overhead_iv[1] = (u8)(trunc_iv >> 16);
	overhead_iv[2] = (u8)(trunc_iv >> 8);
	*overhead_mac = getLE(mac);

	return 0;
}

int calico_datagram_decrypt(calico_state *S, void *ciphertext, int bytes, const void *overhead) {
	calico_internal_state *state = (calico_internal_state *)S;

	// If input is invalid or Calico object is not keyed,
	if (!m_initialized || !state || !ciphertext || !overhead ||
		bytes < 0 || state->flag != FLAG_KEYED_DATAGRAM) {
		return -1;
	}

	const u8 *overhead_iv = reinterpret_cast<const u8 *>( overhead );
	const u64 *overhead_mac = reinterpret_cast<const u64 *>( overhead_iv + 3 );

	// Grab the MAC
	u64 mac = getLE(*overhead_mac);

	// Grab the obfuscated IV
	u32 trunc_iv = ((u32)overhead_iv[2] << 8) | ((u32)overhead_iv[1] << 16) | (u32)overhead_iv[0];

	// De-obfuscate the truncated IV
	trunc_iv ^= IV_FUZZ;
	trunc_iv += (u32)mac;
	trunc_iv &= IV_MASK;

	// Reconstruct the full IV counter
	u64 iv = ReconstructCounter<IV_BITS>(state->window.datagram_remote, trunc_iv);

	// Validate IV
	if (!antireplay_check(&state->window, iv)) {
		return -1;
	}

	// Decrypt and check MAC
	if (!chacha_decrypt(&state->remote, state->remote.datagram_key, iv, ciphertext, plaintext_bytes, mac)) {
		return -1;
	}

	// Accept this IV
	antireplay_accept(&state->window, iv);

	*ciphertext_bytes = plaintext_bytes;

	return 0;
}

int calico_stream_encrypt(void *S, void *ciphertext, const void *plaintext, int bytes, void *overhead) {
	calico_internal_state *state = (calico_internal_state *)S;

	// If input is invalid or Calico is not keyed,
	if (!m_initialized || !state || !plaintext || !ciphertext || bytes < 0 || !overhead ||
		(state->flag != FLAG_KEYED_STREAM && state->flag != FLAG_KEYED_DATAGRAM)) {
		return -1;
	}

	// Select next IV
	const u64 iv = state->stream_local++;

	// Encrypt and generate MAC
	u64 mac = chacha_encrypt(&state->local, state->local.stream_key, iv, plaintext, ciphertext, plaintext_bytes);

	// Write MAC
	u64 *overhead_mac = reinterpret_cast<u64 *>( overhead );
	*overhead_mac = getLE(mac);

	return 0;
}

int calico_stream_decrypt(void *S, void *ciphertext, int bytes, const void *overhead) {
	calico_internal_state *state = (calico_internal_state *)S;

	// If input is invalid or Calico object is not keyed,
	if (!m_initialized || !state || !ciphertext || !overhead || bytes < 0 ||
		(state->flag != FLAG_KEYED_STREAM && state->flag != FLAG_KEYED_DATAGRAM)) {
		return -1;
	}

	// Get next expected IV
	u64 iv = state->stream_remote;

	// Read MAC
	const u64 *overhead_mac = reinterpret_cast<const u64 *>( overhead );
	u64 mac = getLE(*overhead_mac);

	// Decrypt and check MAC
	if (!chacha_decrypt(&state->remote, state->remote.stream_key, iv, ciphertext, plaintext_bytes, mac)) {
		return -1;
	}

	// Advance IV on success
	state->stream_remote = iv + 1;

	return 0;
}

void calico_cleanup(void *S) {
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

