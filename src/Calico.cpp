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

#include "ChaChaVMAC.hpp"
#include "AntiReplayWindow.hpp"
using namespace cat;


// IV constants
static const int IV_BYTES = 3;
static const int IV_BITS = IV_BYTES * 8;
static const u32 IV_MSB = (1 << IV_BITS);
static const u32 IV_MASK = (IV_MSB - 1);
static const u32 IV_FUZZ = 0x9F286AD7;


typedef struct {
	antireplay_state window;
	chacha_vmac_state local, remote;
} calico_internal_state;

static bool m_initialized = false;

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

int calico_key(calico_state *S, int role, const char key[32]) {
	calico_internal_state *state = (calico_internal_state *)S;

	// If input is invalid,
	if (!m_initialized || !key || !S) {
		return -1;
	}

	// If role is invalid,
	if (role != CALICO_INITIATOR && role != CALICO_RESPONDER) {
		return -1;
	}

	// Expand key into two keys using ChaCha20:

	static const int KEY_BYTES = 224;

	u8 keys[KEY_BYTES + KEY_BYTES];
	chacha_key_expand(key, keys, sizeof(keys));

	// Swap keys based on mode
	u8 *lkey = keys, *rkey = keys;
	if (role == CALICO_INITIATOR) lkey += KEY_BYTES;
	else rkey += KEY_BYTES;

	// Initialize the hash
	memcpy(&state->local_hash, lkey, 160);
	memcpy(&state->remote_hash, rkey, 160);
	vhash_set_key(&state->local_hash);
	vhash_set_key(&state->remote_hash);

	// Initialize the cipher
	memcpy(&state->local_cipher, lkey + 160, 64);
	memcpy(&state->remote_cipher, rkey + 160, 64);

	// Grab the IVs from the key bytes
	u64 liv = getLE(*(u64*)(lkey + 160 + 64));
	u64 riv = getLE(*(u64*)(rkey + 160 + 64));

	// Initialize the IV subsystem
	antireplay_init(&state->window, liv, riv);

	CAT_SECURE_OBJCLR(keys);

	return 0;
}

int calico_encrypt(calico_state *S, const void *plaintext, int plaintext_bytes, void *ciphertext, int *ciphertext_bytes_ptr) {

	// If input is invalid,
	if (!m_initialized || !S || !plaintext || !ciphertext ||
		plaintext_bytes < 0 || !ciphertext_bytes || *ciphertext_bytes < 0) {
		return -1;
	}

	// If plaintext bytes are too high,
	if (plaintext_bytes > INT_MAX - CALICO_OVERHEAD) {
		return -1;
	}

	// If ciphertext bytes are not large enough,
	int ciphertext_bytes = *ciphertext_bytes_ptr;
	if (plaintext_bytes + CALICO_OVERHEAD > ciphertext_bytes) {
		return -1;
	}

	// Select next IV
	const u64 iv = state->window.local++;

	chacha_iv civ;
	*(u64*)&civ = getLE64(iv);

	chacha_state cipher;
	chacha_init(&cipher, (const chacha_key *)state->local_key, &civ, 20);

	char mac[8] = {0};
	chacha_update(&cipher, (u8 *)mac, (u8 *)mac, 8);
	chacha_update(&cipher, (u8 *)plaintext

	chacha((const chacha_key *)state->local_key, &civ, plaintext, ciphertext, plaintext_bytes, 20);

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
	*ciphertext_bytes = plaintext_bytes + CALICO_OVERHEAD;

	return 0;
}

int calico_decrypt(calico_state *S, void *ciphertext, int *ciphertext_bytes) {
	// If IV is invalid,
	if (!antireplay_check(&state->window, iv)) {
		return -1;
	}

	// Accept IV
	antireplay_accept(&state->window, iv);

	return 0;
}

int calico_cleanup(calico_state *S) {
	return 0;
}

#ifdef __cplusplus
}
#endif


















int Calico::Initialize(const void *key,				// Pointer to key material
					   const char *session_name,	// Unique session name
					   int mode)					// Value from CalicoModes
{
	_initialized = false;

	if (!key || !session_name)
		return ERR_BAD_INPUT;
	if (mode < INITIATOR || mode > RESPONDER)
		return ERR_BAD_INPUT;

	// Derive a key from given key and session name
	u8 derived_key[64];
	if (0 != blake2b(derived_key, session_name, key, 64, strlen(session_name), 32))
		return ERR_INTERNAL;

	// Expand derived key using ChaCha function
	u8 keys[200 + 200];
	expandKey(derived_key, keys);

	// Swap keys based on mode
	u8 *lkey = keys, *rkey = keys;
	if (mode == CALICO_INITIATOR) lkey += 200;
	else rkey += 200;

	// Initialize the cipher with these keys
	_cipher.Initialize(lkey, rkey);

	// Grab the IVs from the key bytes
	u64 liv = getLE(*(u64*)(lkey + 192));
	u64 riv = getLE(*(u64*)(rkey + 192));

	// Initialize the IV subsystem
	_window.Initialize(liv, riv);

	_initialized = true;

	CAT_SECURE_OBJCLR(keys);

	return ERR_GROOVY;
}

int Calico::Encrypt(const void *plaintext,	// Pointer to input plaintext
					int plaintext_bytes, 	// Input buffer size
					void *ciphertext,		// Pointer to output ciphertext
					int ciphertext_bytes)	// Output buffer size
{
	if (!_initialized)
		return ERR_BAD_STATE;
	if (!plaintext || plaintext_bytes < 0 || !ciphertext)
		return ERR_BAD_INPUT;
	if (plaintext_bytes > INT_MAX - OVERHEAD)
		return ERR_TOO_SMALL;
	if (plaintext_bytes + OVERHEAD > ciphertext_bytes)
		return ERR_TOO_SMALL;

	// Get next outgoing IV
	u64 iv = _window.NextLocal();

	// Encrypt data and slap on a MAC
	_cipher.Encrypt(iv, plaintext, ciphertext, plaintext_bytes);

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

	return plaintext_bytes + OVERHEAD;
}

int Calico::Decrypt(void *ciphertext,		// Pointer to ciphertext
					int ciphertext_bytes)	// Number of valid encrypted data bytes
{
	if (!_initialized)
		return ERR_BAD_STATE;
	if (!ciphertext)
		return ERR_BAD_INPUT;
	if (ciphertext_bytes < INT_MIN + OVERHEAD)
		return ERR_TOO_SMALL;

	int plaintext_bytes = ciphertext_bytes - OVERHEAD;
	if (plaintext_bytes < 0)
		return ERR_TOO_SMALL;

	u8 *overhead8 = reinterpret_cast<u8*>( ciphertext ) + plaintext_bytes;
	u32 *overhead32 = reinterpret_cast<u32*>( overhead8 );

	// Grab the obfuscated IV
	u32 trunc_iv = ((u32)overhead8[10] << 8) | ((u32)overhead8[9] << 16) | (u32)overhead8[8];

	// De-obfuscate the truncated IV
	trunc_iv ^= IV_FUZZ;
	trunc_iv += getLE(*overhead32);
	trunc_iv &= IV_MASK;

	// Reconstruct the full IV counter
	u64 iv = ReconstructCounter<IV_BITS>(_window.LastAccepted(), trunc_iv);

	// Validate IV
	if (!_window.Validate(iv))
		return ERR_IV_DROP;

	// Decrypt and check MAC
	if (!_cipher.Decrypt(iv, ciphertext, plaintext_bytes))
		return ERR_MAC_DROP;

	// Accept this IV
	_window.Accept(iv);

	return plaintext_bytes;
}
