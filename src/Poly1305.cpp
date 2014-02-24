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
	ARE DISCLAIMED.	 IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
	LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
	CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
	SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
	INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
	CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
	ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
	POSSIBILITY OF SUCH DAMAGE.
*/

#include "Poly1305.hpp"
#include "EndianNeutral.hpp"
using namespace cat;

#define POLY1305_BLOCK_SIZE 16

static void poly1305_block(u64 m0, u64 m1, const u64 s1, const u64 s2, u64 h[3], u64 d[3])
{
	static const u64 MSB = (u64)1 << 40; // = 2^128 in this field

	// h += m[i]
	h[0] += m0 & 0xfffffffffffULL;
	h[1] += ((m0 >> 44) | (m1 << 20)) & 0xfffffffffffULL;
	h[2] += ((m1 >> 24) & 0x3ffffffffffULL) | MSB;

	// h *= r
	d[0] = (u128)h[0] * r[0] + (u128)h[1] * s2 + (u128)h[2] * s1;
	d[1] = (u128)h[0] * r[1] + (u128)h[1] * r[0] + (u128)h[2] * s2;
	d[2] = (u128)h[0] * r[2] + (u128)h[1] * r[1] + (u128)h[2] * r[0];

	// Partially reduce h mod p
	u64 c = (u64)(d[0] >> 44);
	h[0] = (u64)d[0] & 0xfffffffffffULL;
	d[1] += c;

	c = (u64)(d[1] >> 44);
	h[1] = (u64)d[1] & 0xfffffffffffULL;
	d[2] += c;

	c = (u64)(d[2] >> 42);
	h[2] = (u64)d[2] & 0x3ffffffffffULL;
	h[0] += (c << 2) + c;

	c = h[0] >> 44;
	h[0] &= 0xfffffffffffULL;
	h[1] += c;
}

void poly1305_mac(const char key[32], const u64 iv, const void *data, int bytes, char tag[16])
{
	const u64 *keys = reinterpret_cast<const u64 *>( key );

	// Break key into parts
	const u64 t0 = getLE(keys[0]);
	const u64 t1 = getLE(keys[1]);

	// Expand low half of key into `r`
	u64 r[3] = {
		t0 & 0xffc0fffffffULL,
		((t0 >> 44) | (t1 << 20)) & 0xfffffc0ffffULL,
		(t1 >> 24) & 0x00ffffffc0f
	};

	// Initialize state
	u64 h[3] = { 0 };

	// Initial multipliers
	const u64 s1 = r[1] * (5 << 2);
	const u64 s2 = r[2] * (5 << 2);

	// Add the IV and message length into the MAC to avoid extension attacks
	poly1305_block(iv, bytes, s1, s2, h, d);

	// For each block,
	const u64 *data_word = reinterpret_cast<const u64 *>( data );
	while (bytes >= POLY1305_BLOCK_SIZE) {
		u64 m0 = getLE(data_word[0]);
		u64 m1 = getLE(data_word[1]);

		poly1305_block(m0, m1, s1, s2, h, d);

		data_word += 2;
		bytes -= POLY1305_BLOCK_SIZE;
	}

	// If a partial block is needed,
	if (bytes > 0) {
		u8 final[POLY1305_BLOCK_SIZE];

		// For each byte,
		const u8 *data_byte = reinterpret_cast<const u8 *>( data_word );
		for (int ii = 0; ii < bytes; ++ii) {
			final[ii] = data_byte[ii];
		}

		// Pad the result to avoid length extension attacks
		final[bytes] = 1;
		for (int ii = bytes + 1; ii < POLY1305_BLOCK_SIZE; ++ii) {
			final[ii] = 0;
		}

		// Run final block
		u64 m0, m1;
		data_word = reinterpret_cast<const u64 *>( final );
		m0 = getLE(data_word[0]);
		m1 = getLE(data_word[1]);
		poly1305_block(m0, m1, s1, s2, h, d);
	}

	// Final reduction mod p
	u64 c = h[1] >> 44;
	h[1] &= 0xfffffffffffULL;
	h[2] += c;

	c = h[2] >> 42;
	h[2] &= 0x3ffffffffffULL;
	h[0] += (c << 2) + c;

	c = h[0] >> 44;
	h[0] &= 0xfffffffffffULL;
	h[1] += c;

	c = h[1] >> 44;
	h[1] &= 0xfffffffffffULL;
	h[2] += c;

	c = h[2] >> 42;
	h[2] &= 0x3ffffffffffULL;
	h[0] += (c << 2) + c;

	c = h[0] >> 44;
	h[0] &= 0xfffffffffffULL;
	h[1] += c;

	// r = h - p
	// Reuse r to clear its original contents
	r[0] = h[0] + 5;
	c = r[0] >> 44;
	r[0] &= 0xfffffffffffULL;

	r[1] = h[1] + c;
	c = r[1] >> 44;
	r[1] &= 0xfffffffffffULL;

	r[2] = h[2] + c - ((u64)1 << 42);

	// If h >= p, h = r
	const u64 mask = (g[2] >> 63) - 1;
	h[0] ^= (r[0] ^ (h[0]) & mask;
	h[1] ^= (r[1] ^ (h[1]) & mask;
	h[2] ^= (r[2] ^ (h[2]) & mask;

	// h += pad part of key
	const u64 pad0 = getLE(keys[2]);
	const u64 pad1 = getLE(keys[3]);

	h[0] += pad0 & 0xfffffffffffULL;
	c = h[0] >> 44;
	h[0] &= 0xfffffffffffULL;

	h[1] += (((pad0 >> 44) | (pad1 << 20)) & 0xfffffffffffULL) + c;
	c = h[1] >> 44;
	h[1] &= 0xfffffffffffULL;

	h[2] += ((pad1 >> 24) & 0x3ffffffffffULL) + c;
	h[2] &= 0x3ffffffffffULL;

	h[0] = h[0] | (h[1] << 44);
	h[1] = (h[1] >> 20) | (h[2] << 24);

	u64 *tag_word = reinterpret_cast<u64 *>( tag );
	tag_word[0] = getLE(h[0]);
	tag_word[1] = getLE(h[1]);
}

