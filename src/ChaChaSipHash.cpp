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
	ARE DISCLAIMED.	 IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
	LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
	CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
	SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
	INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
	CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
	ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
	POSSIBILITY OF SUCH DAMAGE.
*/

#include "ChaChaSipHash.hpp"
#include "EndianNeutral.hpp"
#include "SipHash.hpp"
using namespace cat;

#include "chacha.h"

// Using the internal chacha_blocks() function to speed up invalid message rejection
extern "C" void chacha_blocks_impl(chacha_state_t *state, const uint8_t *in, uint8_t *out, size_t bytes);

bool cat::chacha_key_expand(const char key[32], void *buffer, int bytes) {
	if (bytes % 64) {
		return false;
	}

	chacha_iv iv = {{ 0 }};

	chacha((const chacha_key *)key, &iv, 0, (u8 *)buffer, bytes, 20);

	return true;
}

void cat::chacha_encrypt(const char hash_key[16], const char cipher_key[32],
						 u64 iv_counter, const void *from, void *to, int bytes)
{
	const u64 iv = getLE64(iv_counter);

	chacha_state S;
	chacha_init(&S, (const chacha_key *)cipher_key, (const chacha_iv *)&iv, 14);

	u8 x[64];
	const u32 *keys32 = reinterpret_cast<const u32 *>( x );
	chacha_blocks_impl(&S, 0, x, 64);

	// Store the last two keystream words for encrypting the MAC later
	u32 mac_keystream[2] = {
		keys32[14],
		keys32[15]
	};

	// Encrypt the data:

	const u32 *from32 = reinterpret_cast<const u32 *>( from );
	u32 *to32 = reinterpret_cast<u32 *>( to );
	int left = bytes;

	// If we have enough keystream to cover the whole buffer,
	if (left > 56) {
		// Encrypt using the full remainder of keystream
		for (int ii = 0; ii < 14; ++ii) {
			to32[ii] = from32[ii] ^ keys32[ii];
		}

		// Increment data pointer
		from32 += 14;
		to32 += 14;
		left -= 56;

		chacha_blocks_impl(&S, (const u8 *)from32, (u8 *)to32, left);
	} else {
		int words = left / 4;

		for (int ii = 0; ii < words; ++ii) {
			to32[ii] = from32[ii] ^ keys32[ii];
		}

		// Handle final <4 bytes
		int remainder = left % 4;
		if (remainder > 0) {
			const u8 *keys8 = reinterpret_cast<const u8 *>( keys32 + words );
			const u8 *from8 = reinterpret_cast<const u8 *>( from32 + words );
			u8 *to8 = reinterpret_cast<u8 *>( to32 + words );

			switch (remainder) {
			case 3: to8[2] = from8[2] ^ keys8[2];
			case 2: to8[1] = from8[1] ^ keys8[1];
			case 1: to8[0] = from8[0] ^ keys8[0];
			}
		}
	}

	// Attach MAC:
	{
		// Hash the encrypted buffer
		u64 mac = siphash24(hash_key, to, bytes);

		u8 *to8 = reinterpret_cast<u8 *>( to );
		u32 *overhead = reinterpret_cast<u32 *>( to8 + bytes );

		// Encrypt and attach the MAC to the end
		overhead[0] = getLE((u32)mac) ^ mac_keystream[0];
		overhead[1] = getLE((u32)(mac >> 32)) ^ mac_keystream[1];
	}
}

bool cat::chacha_decrypt(const char hash_key[16], const char cipher_key[32],
						 u64 iv_counter, void *buffer, int bytes)
{
	const u64 iv = getLE64(iv_counter);

	chacha_state S;
	chacha_init(&S, (const chacha_key *)cipher_key, (const chacha_iv *)&iv, 14);

	u8 x[64];
	const u32 *keys32 = reinterpret_cast<const u32 *>( x );
	chacha_blocks_impl(&S, 0, x, 64);

	// Store the last two keystream words for decrypting the MAC
	u32 mac_keystream[2] = {
		keys32[14],
		keys32[15]
	};

	// Recover and verify MAC:
	{
		// Hash the encrypted buffer
		u64 mac = siphash24(hash_key, buffer, bytes);

		u8 *text8 = reinterpret_cast<u8 *>( buffer );
		const u32 *overhead = reinterpret_cast<const u32 *>( text8 + bytes );

		// If generated MAC does not match the provided MAC,
		u32 delta = getLE(overhead[0] ^ mac_keystream[0]) ^ (u32)mac;
		delta |= getLE(overhead[1] ^ mac_keystream[1]) ^ (u32)(mac >> 32);

		if (delta != 0) {
			return false;
		}
	}

	// Decrypt the data:

	u32 *text = reinterpret_cast<u32 *>( buffer );
	int left = bytes;

	// If we have enough keystream to cover the whole buffer,
	if (left > 56) {
		// Decrypt using the full remainder of keystream
		for (int ii = 0; ii < 14; ++ii) {
			text[ii] ^= keys32[ii];
		}

		// Increment data pointer
		text += 14;
		left -= 56;

		chacha_blocks_impl(&S, (const u8 *)text, (u8 *)text, left);
	} else {
		int words = left / 4;

		for (int ii = 0; ii < words; ++ii) {
			text[ii] ^= keys32[ii];
		}

		// Handle final <4 bytes
		int remainder = left % 4;
		if (remainder > 0) {
			const u8 *keys8 = reinterpret_cast<const u8 *>( keys32 + words );
			u8 *text8 = reinterpret_cast<u8 *>( text + words );

			switch (remainder) {
			case 3: text8[2] ^= keys8[2];
			case 2: text8[1] ^= keys8[1];
			case 1: text8[0] ^= keys8[0];
			}
		}
	}

	return true;
}

