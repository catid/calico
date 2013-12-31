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

#include "calico.h"

#include "ChaChaSipHash.hpp"
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
	antireplay_state window;
	chacha_vmac_state local, remote;
	u32 flag;
} calico_internal_state;

static bool m_initialized = false;
static const u32 FLAG_KEYED = 0x6501ccef;

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

	static const int KEY_BYTES = sizeof(chacha_vmac_state) + 16;

	char keys[KEY_BYTES + KEY_BYTES];
	if (!chacha_key_expand((const char *)key, keys, sizeof(keys))) {
		return -1;
	}

	// Swap keys based on mode
	char *lkey = keys, *rkey = keys;
	if (role == CALICO_INITIATOR) lkey += KEY_BYTES;
	else rkey += KEY_BYTES;

	// Set up the ChaCha and SipHash keys
	memcpy(&state->local, lkey, sizeof(chacha_vmac_state));
	memcpy(&state->remote, rkey, sizeof(chacha_vmac_state));

	// Grab the IVs from the key bytes
	const u64 *local_ivs = reinterpret_cast<const u64 *>( lkey + sizeof(chacha_vmac_state) );
	const u64 *remote_ivs = reinterpret_cast<const u64 *>( rkey + sizeof(chacha_vmac_state) );
	u64 datagram_local = getLE(local_ivs[0]);
	u64 stream_local = getLE(local_ivs[1]);
	u64 datagram_remote = getLE(remote_ivs[0]);
	u64 stream_remote = getLE(remote_ivs[1]);

	// Initialize the IV subsystem
	antireplay_init(&state->window, datagram_local, datagram_remote, stream_local, stream_remote);

	CAT_SECURE_OBJCLR(keys);

	// Flag as keyed
	state->flag = FLAG_KEYED;

	return 0;
}

int calico_datagram_encrypt(calico_state *S, const void *plaintext, int plaintext_bytes, void *ciphertext, int *ciphertext_bytes_ptr) {
	calico_internal_state *state = (calico_internal_state *)S;

	// If input is invalid or Calico is not keyed,
	if (!m_initialized || !state || !plaintext || !ciphertext ||
		plaintext_bytes < 0 || !ciphertext_bytes_ptr || state->flag != FLAG_KEYED) {
		return -1;
	}

	// If plaintext bytes are too high,
	if (plaintext_bytes > INT_MAX - CALICO_DATAGRAM_OVERHEAD) {
		return -1;
	}

	// If ciphertext bytes are not large enough,
	int ciphertext_bytes = *ciphertext_bytes_ptr;
	if (plaintext_bytes + CALICO_DATAGRAM_OVERHEAD > ciphertext_bytes) {
		return -1;
	}

	// Select next IV
	const u64 iv = state->window.datagram_local++;

	chacha_encrypt(state->local.hash_key, state->local.datagram_key, iv, plaintext, ciphertext, plaintext_bytes);

	// Attach IV to the end:

	u8 *overhead8 = reinterpret_cast<u8*>( ciphertext ) + plaintext_bytes;
	const u32 *overhead32 = reinterpret_cast<const u32*>( overhead8 );

	// Obfuscate the truncated IV
	u32 trunc_iv = (u32)iv;
	trunc_iv -= getLE(*overhead32);
	trunc_iv ^= IV_FUZZ;

	// Append it to the data
	overhead8[8] = (u8)trunc_iv;
	overhead8[9] = (u8)(trunc_iv >> 16);
	overhead8[10] = (u8)(trunc_iv >> 8);

	// Set ciphertext bytes
	*ciphertext_bytes_ptr = plaintext_bytes + CALICO_DATAGRAM_OVERHEAD;

	return 0;
}

int calico_datagram_decrypt(calico_state *S, void *ciphertext, int *ciphertext_bytes) {
	calico_internal_state *state = (calico_internal_state *)S;

	// If input is invalid or Calico object is not keyed,
	if (!m_initialized || !state || !ciphertext || !ciphertext_bytes ||
		*ciphertext_bytes < 0 || state->flag != FLAG_KEYED) {
		return -1;
	}

	// If too small,
	if (*ciphertext_bytes < INT_MIN + CALICO_DATAGRAM_OVERHEAD) {
		return -1;
	}

	// It too large,
	int plaintext_bytes = *ciphertext_bytes - CALICO_DATAGRAM_OVERHEAD;
	if (plaintext_bytes < 0) {
		return -1;
	}

	u8 *overhead8 = reinterpret_cast<u8*>( ciphertext ) + plaintext_bytes;
	u32 *overhead32 = reinterpret_cast<u32*>( overhead8 );

	// Grab the obfuscated IV
	u32 trunc_iv = ((u32)overhead8[10] << 8) | ((u32)overhead8[9] << 16) | (u32)overhead8[8];

	// De-obfuscate the truncated IV
	trunc_iv ^= IV_FUZZ;
	trunc_iv += getLE(*overhead32);
	trunc_iv &= IV_MASK;

	// Reconstruct the full IV counter
	u64 iv = ReconstructCounter<IV_BITS>(state->window.datagram_remote, trunc_iv);

	// Validate IV
	if (!antireplay_check(&state->window, iv)) {
		return -1;
	}

	// Decrypt and check MAC
	if (!chacha_decrypt(state->remote.hash_key, state->remote.datagram_key, iv, ciphertext, plaintext_bytes)) {
		return -1;
	}

	// Accept this IV
	antireplay_accept(&state->window, iv);

	*ciphertext_bytes = plaintext_bytes;

	return 0;
}

int calico_stream_encrypt(calico_state *S, const void *plaintext, int plaintext_bytes, void *ciphertext, int *ciphertext_bytes_ptr) {
	calico_internal_state *state = (calico_internal_state *)S;

	// If input is invalid or Calico is not keyed,
	if (!m_initialized || !state || !plaintext || !ciphertext ||
		plaintext_bytes < 0 || !ciphertext_bytes_ptr || state->flag != FLAG_KEYED) {
		return -1;
	}

	// If plaintext bytes are too high,
	if (plaintext_bytes > INT_MAX - CALICO_STREAM_OVERHEAD) {
		return -1;
	}

	// If ciphertext bytes are not large enough,
	int ciphertext_bytes = *ciphertext_bytes_ptr;
	if (plaintext_bytes + CALICO_STREAM_OVERHEAD > ciphertext_bytes) {
		return -1;
	}

	// Select next IV
	const u64 iv = state->window.stream_local++;

	chacha_encrypt(state->local.hash_key, state->local.stream_key, iv, plaintext, ciphertext, plaintext_bytes);

	// Set ciphertext bytes
	*ciphertext_bytes_ptr = plaintext_bytes + CALICO_STREAM_OVERHEAD;

	return 0;
}

int calico_stream_decrypt(calico_state *S, void *ciphertext, int *ciphertext_bytes) {
	calico_internal_state *state = (calico_internal_state *)S;

	// If input is invalid or Calico object is not keyed,
	if (!m_initialized || !state || !ciphertext || !ciphertext_bytes ||
		*ciphertext_bytes < 0 || state->flag != FLAG_KEYED) {
		return -1;
	}

	// If too small,
	if (*ciphertext_bytes < INT_MIN + CALICO_STREAM_OVERHEAD) {
		return -1;
	}

	// It too large,
	int plaintext_bytes = *ciphertext_bytes - CALICO_STREAM_OVERHEAD;
	if (plaintext_bytes < 0) {
		return -1;
	}

	u64 iv = state->window.stream_remote;

	// Decrypt and check MAC
	if (!chacha_decrypt(state->remote.hash_key, state->remote.stream_key, iv, ciphertext, plaintext_bytes)) {
		return -1;
	}

	// Advance IV on success
	state->window.stream_remote = iv + 1;

	*ciphertext_bytes = plaintext_bytes;

	return 0;
}

void calico_cleanup(calico_state *S) {
	if (!S) {
		cat_secure_erase(S, sizeof(calico_internal_state));
	}
}

#ifdef __cplusplus
}
#endif

