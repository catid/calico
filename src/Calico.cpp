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

//#define CAT_VERBOSE_CALICO

#include "calico.h"

#include "AntiReplayWindow.hpp"
#include "EndianNeutral.hpp"
#include "SecureErase.hpp"
#include "BitMath.hpp"
#include "Clock.hpp"
#include "SipHash.hpp"
using namespace cat;

#include <climits>

#include "chacha.h"
#include "blake2.h"

#ifndef CAT_CHACHA_IMPL
#define chacha_blocks_impl chacha_blocks_ref
#endif

// Debug output
#ifdef CAT_VERBOSE_CALICO
#include <iostream>
using namespace std;
#define CAT_LOG(x) x
#else
#define CAT_LOG(x)
#endif

// Using the internal chacha_blocks() function to speed up invalid message rejection
extern "C" void chacha_blocks_impl(chacha_state_t *state, const uint8_t *in, uint8_t *out, size_t bytes);

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

// One-way key information
struct HalfDuplexKey {
	// This is either 0 or 1 to indicate which of the two incoming
	// keys is "active"; the other key is "inactive" and will be
	// set to H(K_active)
	u32 active;

	// Next IV
	// NOTE: This is unused for datagram decryption
	u64 iv;
};

struct Key {
	// Encryption and MAC key for outgoing data
	char out_key[KEY_BYTES];

	// Current and next encryption keys for incoming data
	char in_key[2][KEY_BYTES];

	HalfDuplexKey in, out;
};

#ifndef RATCHET_REMOTE_TIMEOUT
// This is the time after the receiver sees a remote key switch past
// which the receiver will ratchet the remote key to forget the old one
static const u32 RATCHET_REMOTE_TIMEOUT = 60 * 1000; // 1 minute in milliseconds
#endif

#ifndef RATCHET_PERIOD
// Minimum time between rekeying
static const u32 RATCHET_PERIOD = 2 * RATCHET_REMOTE_TIMEOUT; // 2 minutes in milliseconds
#endif

// Constants to indicate the Calico state object is keyed
static const u32 FLAG_KEYED_STREAM = 0x6501ccef;
static const u32 FLAG_KEYED_DATAGRAM = 0x6501ccfe;

struct InternalState {
	// Flag indicating whether or not the Calico state object is keyed or not
	u32 flag;

	// Role of the connection, either CALICO_INITIATOR, CALICO_RESPONDER
	u32 role;

	// Encryption and MAC keys for stream mode
	Key stream;

	// --- Extended version for datagrams: ---

	// Encryption and MAC keys for datagram mode
	Key dgram;

	// Anti-replay window for incoming datagram IVs
	antireplay_state window;

	// This is the millisecond timestamp when incoming ratcheting started.
	// Otherwise it is set to 0 when ratcheting is not in progress
	u32 dgram_in_ratchet_time;

	// Set to last time ratchet occurred on the Initiator
	u32 dgram_out_ratchet_time;
};

// Flag to indicate that the library has been initialized with calico_init()
static bool m_initialized = false;

static Clock m_clock;


// Helper function to ratchet a key
static int ratchet_key(const char key[KEY_BYTES], char next_key[KEY_BYTES]) {
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

	return 0;
}

// Helper function to expand key using ChaCha20
static bool key_expand(const char key[32], void *buffer, int bytes)
{
	if (bytes % 64) {
		return false;
	}

	chacha_iv iv = {{ 0 }};

	chacha((const chacha_key *)key, &iv, 0, (u8 *)buffer, bytes, 20);

	return true;
}

// Helper function to do the basic authenticated encryption
static u64 auth_encrypt(const char key[48], u64 iv_raw, const void *from,
						void *to, int bytes)
{
	const u64 iv = getLE(iv_raw);

	// Setup the cipher with the key and IV
	chacha_state S;
	chacha_init(&S, (const chacha_key *)key, (const chacha_iv *)&iv, 14);

	// Encrypt data
	chacha_blocks_impl(&S, (const u8 *)from, (u8 *)to, bytes);

	// Generate MAC tag
	return siphash24(key + 32, to, bytes, iv);
}

// Helper function to conditionally perform key ratchet on receiver side
static void handle_ratchet(InternalState *state) {
	// If ratchet time exceeded,
	if ((u32)(m_clock.msec() - state->dgram_in_ratchet_time) > RATCHET_REMOTE_TIMEOUT) {
		Key *key = &state->dgram;

		CAT_LOG(cout << "--Ratcheting key!" << endl);

		// Get active and inactive key
		const u32 active_key = key->in.active;
		const u32 inactive_key = active_key ^ 1;

		/*
		* Before:
		*
		*	K[active] = oldest key
		*	K[inactive] = H(oldest key)
		*/

		// Update the inactive key: K' = H(K)
		ratchet_key(key->in_key[inactive_key], key->in_key[active_key]);

		/*
		* After:
		*
		*	K[inactive] = H(H(oldest key))
		*	K[active] = H(oldest key)
		*
		* The oldest key is now erased.
		*/

		// Switch which key is active
		key->in.active = inactive_key;

		// Ratchet complete
		state->dgram_in_ratchet_time = 0;
	}
}

// Helper function to authenticate a message
static bool check_auth(const char key[48], u64 iv, int shift,
					const void *buffer, int bytes, u64 tag)
{
	// Generate expected MAC tag
	const u64 expected_tag = siphash24(key + 32, buffer, bytes, iv) << shift;

	// Verify MAC tag in constant-time
	const u64 delta = (expected_tag ^ tag) >> shift;
	const u32 z = (u32)(delta >> 32) | (u32)delta;
	if (z) {
		return false;
	}

	return true;
}

// Helper function to decrypt a message
static void decrypt(const u64 iv_raw, const char key[48], void *buffer, int bytes)
{
	const u64 iv = getLE(iv_raw);

	// Setup the cipher with the key and IV
	chacha_state S;
	chacha_init(&S, (const chacha_key *)key, (const chacha_iv *)&iv, 14);

	// Decrypt data
	chacha_blocks_impl(&S, (const u8 *)buffer, (u8 *)buffer, bytes);
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

	// Make sure clock is initialized
	m_clock.OnInitialize();

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

int calico_key(void *S, int state_size, int role, const void *key, int key_bytes)
{
	InternalState *state = reinterpret_cast<InternalState *>( S );

	// If input is invalid,
	if (!m_initialized || !key || !state || key_bytes != 32) {
		CAT_LOG(cout << "calico_key: Invalid input" << endl);
		return -1;
	}

	// Check state size
	bool datagram_supported;
	if (state_size == sizeof(calico_state)) {
		datagram_supported = true;
		CAT_LOG(cout << "calico_key: Keying datagram mode" << endl);
	} else if (state_size == sizeof(calico_stream_only)) {
		datagram_supported = false;
		CAT_LOG(cout << "calico_key: Keying stream mode" << endl);
	} else {
		// Invalid length
		CAT_LOG(cout << "calico_key: Unsupported state size" << endl);
		return -1;
	}

	// If role is invalid,
	if (role != CALICO_INITIATOR && role != CALICO_RESPONDER) {
		CAT_LOG(cout << "calico_key: Invalid role" << endl);
		return -1;
	}

	// Set flag to unkeyed
	state->flag = 0;

	// Remember role
	state->role = role;

	// Stream and datagram keys for both sides
	static const int COMBINED_BYTES = KEY_BYTES * 2;
	char keys[COMBINED_BYTES * 2];

	// Expand key into two sets of two keys
	if (!key_expand((const char *)key, keys, sizeof(keys))) {
		CAT_LOG(cout << "calico_key: Unable to expand key" << endl);
		return -1;
	}

	// Swap keys based on mode
	char *lkey = keys, *rkey = keys;
	if (role == CALICO_INITIATOR) lkey += COMBINED_BYTES;
	else rkey += COMBINED_BYTES;

	// Copy stream keys into place
	memcpy(state->stream.out_key, lkey, KEY_BYTES);
	memcpy(state->stream.in_key[0], rkey, KEY_BYTES);

	// Generate the next remote key
	if (ratchet_key(state->stream.in_key[0], state->stream.in_key[1])) {
		CAT_LOG(cout << "calico_key: Unable to ratchet stream key" << endl);
		return -1;
	}

	// Mark when ratchet happened
	const u32 msec = m_clock.msec();
	state->dgram_out_ratchet_time = msec; // Only used by initiator
	state->dgram_in_ratchet_time = 0;

	// Set active keys
	state->stream.in.active = 0;
	state->stream.out.active = 0;

	// Initialize the IV subsystem for streams
	state->stream.in.iv = 0;
	state->stream.out.iv = 0;

	// If datagram transport is supported,
	if (datagram_supported) {
		// Copy datagram keys into place
		memcpy(state->dgram.out_key, lkey + KEY_BYTES, KEY_BYTES);
		memcpy(state->dgram.in_key[0], rkey + KEY_BYTES, KEY_BYTES);

		// Generate the next remote key
		if (ratchet_key(state->dgram.in_key[0], state->dgram.in_key[1])) {
			CAT_LOG(cout << "calico_key: Unable to ratchet datagram key" << endl);
			return -1;
		}

		// Set active keys
		state->dgram.in.active = 0;
		state->dgram.out.active = 0;

		// Initialized the IV subsystem for datagrams
		state->dgram.in.iv = 0;
		state->dgram.out.iv = 0;
		// Note that stream.in.iv is unused

		// Set datagram ratchet time
		state->dgram_out_ratchet_time = msec; // Only used by initiator
		state->dgram_in_ratchet_time = 0;

		// Initialize the IV subsystem for datagrams
		antireplay_init(&state->window);

		// Flag as keyed
		state->flag = FLAG_KEYED_DATAGRAM;
	} else {
		// Flag as keyed
		state->flag = FLAG_KEYED_STREAM;
	}

	// Erase temporary keys from memory
	CAT_SECURE_OBJCLR(keys);

	return 0;
}


//// Encryption

int calico_encrypt(void *S, void *ciphertext, const void *plaintext, int bytes,
					void *overhead, int overhead_size)
{
	InternalState *state = reinterpret_cast<InternalState *>( S );

	// If input is invalid or Calico is not keyed,
	if (!m_initialized || !state || !plaintext || !ciphertext || bytes < 0 ||
		!overhead) {
		CAT_LOG(cout << "calico_encrypt: Invalid input" << endl);
		return -1;
	}

	// Select key
	Key *key;
	if (overhead_size == CALICO_DATAGRAM_OVERHEAD) {
		key = &state->dgram;

		// If state is not keyed for datagrams,
		if (state->flag != FLAG_KEYED_DATAGRAM) {
			CAT_LOG(cout << "calico_encrypt: Attempted to use unkeyed datagram mode" << endl);
			return -1;
		}

		CAT_LOG(cout << "calico_encrypt: Encrypting in datagram mode" << endl);
	} else if (overhead_size == CALICO_STREAM_OVERHEAD) {
		key = &state->stream;

		CAT_LOG(cout << "calico_encrypt: Encrypting in stream mode" << endl);
	} else {
		// Invalid input
		return -1;
	}

	// Get next IV
	const u64 iv = key->out.iv;

	// If out of IVs,
	if (iv == 0xffffffffffffffffULL) {
		CAT_LOG(cout << "calico_encrypt: Refusing to continue encrypting after ran out of IVs" << endl);
		return -1;
	}

	// If initiator,
	if (state->role == CALICO_INITIATOR) {
		// If it is time to ratchet the key again,
		if (key->out.active == key->in.active) {
			const u32 msec = m_clock.msec();

			if ((u32)(msec - state->dgram_out_ratchet_time) > RATCHET_PERIOD) {
				CAT_LOG(cout << "calico_encrypt: Ratcheting key" << endl);

				// Ratchet to next key, erasing the old key
				if (ratchet_key(key->out_key, key->out_key)) {
					CAT_LOG(cout << "calico_encrypt: Ratcheting failed" << endl);
					return -1;
				}

				// Flip the active key bit
				key->out.active ^= 1;

				// Update base ratchet time to add another delay
				state->dgram_out_ratchet_time = msec;
			}
		}
	}

	// Increment IV
	key->out.iv = iv + 1;

	// Encrypt and generate MAC tag
	u64 tag = auth_encrypt(key->out_key, iv, plaintext, ciphertext, bytes);

	if (overhead_size == CALICO_DATAGRAM_OVERHEAD) {
		CAT_LOG(cout << "calico_encrypt: Encrypting datagram with IV = " << iv << " and ratchet = " << key->out.active << endl);

		// Obfuscate the truncated IV
		u32 trunc_iv = ((u32)iv << 1) | key->out.active;
		trunc_iv -= (u32)tag;
		trunc_iv ^= AD_FUZZ;

		u64 *overhead_tag = reinterpret_cast<u64 *>( overhead );
		u8 *overhead_iv = reinterpret_cast<u8 *>( overhead_tag + 1 );

		// Store IV and tag
		overhead_iv[0] = (u8)trunc_iv;
		overhead_iv[1] = (u8)(trunc_iv >> 16);
		overhead_iv[2] = (u8)(trunc_iv >> 8);
		*overhead_tag = getLE(tag);
	} else {
		CAT_LOG(cout << "calico_encrypt: Encrypting stream with IV = " << iv << " and ratchet = " << key->out.active << endl);

		// Attach active key bit to tag field
		tag = (tag << 1) | key->out.active;

		u64 *overhead_tag = reinterpret_cast<u64 *>( overhead );

		// Write MAC tag
		*overhead_tag = getLE(tag);
	}

	return 0;
}


//// Decryption

int calico_decrypt(void *S, void *ciphertext, int bytes, const void *overhead,
					int overhead_size)
{
	InternalState *state = reinterpret_cast<InternalState *>( S );

	// If input is invalid or Calico object is not keyed,
	if (!m_initialized || !state || !ciphertext || !overhead || bytes < 0) {
		CAT_LOG(cout << "calico_decrypt: Invalid input" << endl);
		return -1;
	}

	// Select key
	Key *key;
	if (overhead_size == CALICO_DATAGRAM_OVERHEAD) {
		key = &state->dgram;

		// If state is not keyed for datagrams,
		if (state->flag != FLAG_KEYED_DATAGRAM) {
			CAT_LOG(cout << "calico_decrypt: Datagram decryption requested but not keyed" << endl);
			return -1;
		}
		CAT_LOG(cout << "calico_decrypt: Decrypting datagram of bytes = " << bytes << endl);

		// If ratcheting is happening already,
		if (state->dgram_in_ratchet_time) {
			// Handle ratchet update
			handle_ratchet(state);
		}
	} else if (overhead_size == CALICO_STREAM_OVERHEAD) {
		key = &state->stream;
		CAT_LOG(cout << "calico_decrypt: Decrypting stream of bytes = " << bytes << endl);
	} else {
		// Invalid input
		CAT_LOG(cout << "calico_decrypt: Invalid overhead size specified" << endl);
		return -1;
	}

	const u64 *overhead_tag = reinterpret_cast<const u64 *>( overhead );

	// Grab the MAC tag
	const u64 tag = getLE(*overhead_tag);

	u32 ratchet_bit;
	u64 iv;
	int auth_shift;

	if (overhead_size == CALICO_DATAGRAM_OVERHEAD) {
		const u8 *overhead_iv = reinterpret_cast<const u8 *>( overhead_tag + 1 );

		// Grab the obfuscated IV
		u32 trunc_iv = ((u32)overhead_iv[2] << 8) | ((u32)overhead_iv[1] << 16) | (u32)overhead_iv[0];

		// De-obfuscate the truncated IV
		trunc_iv ^= AD_FUZZ;
		trunc_iv += (u32)tag;
		trunc_iv &= AD_MASK;

		// Pull out the ratchet bit
		ratchet_bit = trunc_iv & 1;
		trunc_iv >>= 1;

		// Reconstruct the full IV counter
		iv = ReconstructCounter<IV_BITS>(state->window.newest_iv, trunc_iv);

		CAT_LOG(cout << "calico_decrypt: Decrypting datagram with IV = " << iv << " and ratchet = " << ratchet_bit << endl);

		// Validate IV
		if (!antireplay_check(&state->window, iv)) {
			CAT_LOG(cout << "calico_decrypt: IV was replayed or too old" << endl);
			return -1;
		}

		// Full 64 bits are used for MAC tag
		auth_shift = 0;
	} else {
		// Extract the IV
		iv = key->in.iv;

		// Extract the ratchet bit
		ratchet_bit = (u32)tag & 1;

		CAT_LOG(cout << "calico_decrypt: Decrypting stream with IV = " << iv << " and ratchet = " << ratchet_bit << endl);

		// Shift out the low bit during authentication
		auth_shift = 1;
	}

	// Get deccryption/MAC key
	const char *dec_key = key->in_key[ratchet_bit];

	//// No actions may be taken here until the message is authenticated!

	// Authenticate the message
	if (!check_auth(dec_key, iv, auth_shift, ciphertext, bytes, tag)) {
		CAT_LOG(cout << "calico_decrypt: Message authentication failed" << endl);
		return -1;
	}

	// If the ratchet bit is not the active key,
	if (ratchet_bit ^ key->in.active) {
		// If not already ratcheting,
		if (overhead_size == CALICO_STREAM_OVERHEAD ||
			!state->dgram_in_ratchet_time) {
			CAT_LOG(cout << "calico_decrypt: Detected a key ratchet from remote host" << endl);

			// If datagram,
			if (overhead_size == CALICO_DATAGRAM_OVERHEAD) {
				// Set a timer until the key is erased
				state->dgram_in_ratchet_time = m_clock.msec() | 1; // ensure it is non-zero
			} else {
				 // Update the inactive key: K' = H(K)
				 ratchet_key(key->in_key[ratchet_bit], key->in_key[ratchet_bit ^ 1]);

				 // This will immediately ratchet in Stream mode
				 key->in.active = ratchet_bit;

			}

			// If responder,
			if (state->role == CALICO_RESPONDER) {
				CAT_LOG(cout << "calico_decrypt: Ratcheting key since this is the responder" << endl);
				// This is our trigger to ratchet our encryption key.

				// Ratchet to next key, erasing the old key
				if (ratchet_key(key->out_key, key->out_key)) {
					return -1;
				}

				// Flip the active key bit
				key->out.active ^= 1;
			}
		}
	}

	decrypt(iv, dec_key, ciphertext, bytes);

	if (overhead_size == CALICO_DATAGRAM_OVERHEAD) {
		// Accept this IV
		antireplay_accept(&state->window, iv);
	} else {
		// Update IV
		key->in.iv = iv + 1;
	}

	CAT_LOG(cout << "calico_decrypt: Message decrypted successfully" << endl);

	return 0;
}

#ifdef __cplusplus
}
#endif

