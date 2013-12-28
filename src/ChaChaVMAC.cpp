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

#include "ChaChaVMAC.hpp"
#include "EndianNeutral.hpp"
using namespace cat;

static const int CHACHA_ROUNDS = 14;

#define CHACHA_REGISTERS \
	u32 x[16];

#define CHACHA_STARTMIX \
	x[0] = chacha_key[0]; x[1] = chacha_key[1]; x[2] = chacha_key[2]; x[3] = chacha_key[3]; \
	x[4] = chacha_key[4]; x[5] = chacha_key[5]; x[6] = chacha_key[6]; x[7] = chacha_key[7]; \
	x[8] = 0x61707865; x[9] = 0x3320646e; x[10] = 0x79622d32; x[11] = 0x6b206574; \
	x[12] = (u32)block_counter; x[13] = (u32)(block_counter >> 32); \
	x[14] = (u32)iv_counter; x[15] = (u32)(iv_counter >> 32);

#define CHACHA_ENDMIX \
	x[0] = getLE32(x[0] + chacha_key[0]); \
	x[1] = getLE32(x[1] + chacha_key[1]); \
	x[2] = getLE32(x[2] + chacha_key[2]); \
	x[3] = getLE32(x[3] + chacha_key[3]); \
	x[4] = getLE32(x[4] + chacha_key[4]); \
	x[5] = getLE32(x[5] + chacha_key[5]); \
	x[6] = getLE32(x[6] + chacha_key[6]); \
	x[7] = getLE32(x[7] + chacha_key[7]); \
	x[8] = getLE32(x[8] + 0x61707865); \
	x[9] = getLE32(x[9] + 0x3320646e); \
	x[10] = getLE32(x[10] + 0x79622d32); \
	x[11] = getLE32(x[11] + 0x6b206574); \
	x[12] = getLE32(x[12] + (u32)block_counter); \
	x[13] = getLE32(x[13] + (u32)(block_counter >> 32)); \
	x[14] = getLE32(x[14] + (u32)iv_counter); \
	x[15] = getLE32(x[15] + (u32)(iv_counter >> 32));

#define CHACHA_QUARTERROUND(A,B,C,D) \
        x[A] += x[B]; x[D] = CAT_ROL32(x[D] ^ x[A], 16); \
        x[C] += x[D]; x[B] = CAT_ROL32(x[B] ^ x[C], 12); \
        x[A] += x[B]; x[D] = CAT_ROL32(x[D] ^ x[A], 8); \
        x[C] += x[D]; x[B] = CAT_ROL32(x[B] ^ x[C], 7);

#define CHACHA_RUN(ROUNDS) \
		CHACHA_STARTMIX; \
        for (int round = ROUNDS; round > 0; round -= 2) { \
                CHACHA_QUARTERROUND(0, 4, 8,  12) \
                CHACHA_QUARTERROUND(1, 5, 9,  13) \
                CHACHA_QUARTERROUND(2, 6, 10, 14) \
                CHACHA_QUARTERROUND(3, 7, 11, 15) \
                CHACHA_QUARTERROUND(0, 5, 10, 15) \
                CHACHA_QUARTERROUND(1, 6, 11, 12) \
                CHACHA_QUARTERROUND(2, 7, 8,  13) \
                CHACHA_QUARTERROUND(3, 4, 9,  14) \
        } \
		CHACHA_ENDMIX;

bool cat::chacha_key_expand(const char key[32], void *buffer, int bytes) {
	if (bytes % 64) {
		return false;
	}

#ifdef CAT_ENDIAN_LITTLE
	const u32 *chacha_key = (const u32 *)key;
#else
	const u32 *chacha_key_raw = (const u32 *)key;
	u32 chacha_key[8];
	for (int ii = 0; ii < 8; ++ii) {
		chacha_key[ii] = getLE(chacha_key_raw[ii]);
	}
#endif

	u32 *output = (u32 *)buffer;
	u64 block_counter = 0;
	const u64 iv_counter = 0;

	CHACHA_REGISTERS;

	int blocks = bytes >> 6;
	do {
		CHACHA_RUN(20);

		for (int ii = 0; ii < 16; ++ii) {
			output[ii] = x[ii];
		}
		output += 16;

		++block_counter;

		--blocks;
	} while (blocks > 0);

	return true;
}

bool cat::chacha_key(chacha_vmac_state *state, const char key[32]) {
	if (!chacha_key_expand(key, state, sizeof(chacha_vmac_state))) {
		return false;
	}

	vhash_set_key(&state->hash_state);

	return true;
}

void cat::chacha_encrypt(chacha_vmac_state *state, u64 iv_counter, const void *from, void *to, int bytes)
{
	CHACHA_REGISTERS;

	u64 block_counter = 0;
	const u32 *chacha_key = state->chacha_key;

	CHACHA_RUN(CHACHA_ROUNDS);

	// Store the last two keystream words for encrypting the MAC later
	u32 mac_keystream[2] = {
		x[14],
		x[15]
	};

	// Encrypt the data:

	const u32 *from32 = reinterpret_cast<const u32 *>( from );
	u32 *to32 = reinterpret_cast<u32 *>( to );
	int left = bytes;

	// If we have enough keystream to cover the whole buffer,
	if (left > 56) {
		// Encrypt using the full remainder of keystream
		for (int ii = 0; ii < 14; ++ii) {
			to32[ii] = from32[ii] ^ x[ii];
		}

		// Increment data pointer
		from32 += 14;
		to32 += 14;
		left -= 56;

		// For each remaining full block,
		do {
			++block_counter;
			CHACHA_RUN(CHACHA_ROUNDS);

			if (left < 64) {
				break;
			}

			for (int ii = 0; ii < 16; ++ii) {
				to32[ii] = from32[ii] ^ x[ii];
			}

			from32 += 16;
			to32 += 16;
			left -= 64;
		} while (left > 0);
	}

	// For remainder of final block,
	if (left > 0) {
		int words = left / 4;

		for (int ii = 0; ii < words; ++ii) {
			to32[ii] = from32[ii] ^ x[ii];
		}

		// Handle final <4 bytes
		int remainder = left % 4;
		if (remainder > 0) {
			const u8 *from8 = reinterpret_cast<const u8 *>( from32 + words );
			u8 *to8 = reinterpret_cast<u8 *>( to32 + words );
			u32 final_key = getLE32(x[words]);

			switch (remainder) {
			case 3: to8[2] = from8[2] ^ (u8)(final_key >> 16);
			case 2: to8[1] = from8[1] ^ (u8)(final_key >> 8);
			case 1: to8[0] = from8[0] ^ (u8)final_key;
			}
		}
	}

	// Attach MAC:
	{
		// Hash the encrypted buffer
		u64 mac = vhash(&state->hash_state, to, bytes);

		u8 *to8 = reinterpret_cast<u8 *>( to );
		u32 *overhead = reinterpret_cast<u32 *>( to8 + bytes );

		// Encrypt and attach the MAC to the end
		overhead[0] = getLE((u32)mac) ^ mac_keystream[0];
		overhead[1] = getLE((u32)(mac >> 32)) ^ mac_keystream[1];
	}
}

bool cat::chacha_decrypt(chacha_vmac_state *state, u64 iv_counter, void *buffer, int bytes)
{
	CHACHA_REGISTERS;

	u64 block_counter = 0;
	const u32 *chacha_key = state->chacha_key;

	CHACHA_RUN(CHACHA_ROUNDS);

	// Store the last two keystream words for decrypting the MAC
	u32 mac_keystream[2] = {
		x[14],
		x[15]
	};

	// Recover and verify MAC:
	{
		// Hash the encrypted buffer
		u64 mac = vhash(&state->hash_state, buffer, bytes);

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
			text[ii] ^= x[ii];
		}

		// Increment data pointer
		text += 14;
		left -= 56;

		// For each remaining full block,
		do {
			++block_counter;
			CHACHA_RUN(CHACHA_ROUNDS);

			if (left < 64) {
				break;
			}

			for (int ii = 0; ii < 16; ++ii) {
				text[ii] ^= x[ii];
			}

			text += 16;
			left -= 64;
		} while (left > 0);
	}

	// For remainder of final block,
	if (left > 0) {
		int words = left / 4;

		for (int ii = 0; ii < words; ++ii) {
			text[ii] ^= x[ii];
		}

		// Handle final <4 bytes
		int remainder = left % 4;
		if (remainder > 0) {
			u8 *text8 = reinterpret_cast<u8 *>( text + words );
			u32 final_key = getLE32(x[words]);

			switch (remainder) {
			case 3: text8[2] ^= (u8)(final_key >> 16);
			case 2: text8[1] ^= (u8)(final_key >> 8);
			case 1: text8[0] ^= (u8)final_key;
			}
		}
	}

	return true;
}

