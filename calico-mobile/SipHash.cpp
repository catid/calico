/*
	Copyright (c) 2013 Christopher A. Taylor.  All rights reserved.

	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions are met:

	* Redistributions of source code must retain the above copyright notice,
	  this list of conditions and the following disclaimer.
	* Redistributions in binary form must reproduce the above copyright notice,
	  this list of conditions and the following disclaimer in the documentation
	  and/or other materials provided with the distribution.
	* Neither the name of LibCat nor the names of its contributors may be used
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

#include "SipHash.hpp"
#include "EndianNeutral.hpp"
using namespace cat;

#define SIP_HALF_ROUND(a, b, c, d, s, t) \
	a += b; \
	c += d; \
	b = CAT_ROL64(b, s) ^ a; \
	d = CAT_ROL64(d, t) ^ c; \
	a = CAT_ROL64(a, 32);

#define SIP_DOUBLE_ROUND(v0, v1, v2, v3) \
	SIP_HALF_ROUND(v0, v1, v2, v3, 13, 16); \
	SIP_HALF_ROUND(v2, v1, v0, v3, 17, 21); \
	SIP_HALF_ROUND(v0, v1, v2, v3, 13, 16); \
	SIP_HALF_ROUND(v2, v1, v0, v3, 17, 21);

u64 cat::siphash24(const char key[16], const void *vm, int len) {
	// Convert key into two 64-bit integers
	u64 k0 = getLE(*(const u64 *)key);
	u64 k1 = getLE(*(const u64 *)(key + 8));

	// Mix the key across initial state
	u64 v0 = k0 ^ 0x736f6d6570736575ULL;
	u64 v1 = k1 ^ 0x646f72616e646f6dULL;
	u64 v2 = k0 ^ 0x6c7967656e657261ULL;
	u64 v3 = k1 ^ 0x7465646279746573ULL;

	// Perform SIP rounds on 8 bytes of input at a time
	const u64 *m64 = (const u64 *)vm;
	for (int words = len >> 3; words > 0; --words) {
		u64 mi = getLE(*m64++);

		v3 ^= mi;
		SIP_DOUBLE_ROUND(v0, v1, v2, v3);
		v0 ^= mi;
	}

	// Mix the last 1..7 bytes with the length
	const char *m = (const char *)m64;
	u64 last7 = (u64)len << 56;
	switch (len & 7) {
		case 7: last7 |= (u64)m[6] << 48;
		case 6: last7 |= (u64)m[5] << 40;
		case 5: last7 |= (u64)m[4] << 32;
		case 4: last7 |= getLE(*(const u32 *)m); // low -> low
			break;
		case 3: last7 |= (u64)m[2] << 16;
		case 2: last7 |= (u64)m[1] << 8;
		case 1: last7 |= (u64)m[0];
			break;
	};

	// Final mix
	v3 ^= last7;
	SIP_DOUBLE_ROUND(v0, v1, v2, v3);
	v0 ^= last7;
	v2 ^= 0xff;
	SIP_DOUBLE_ROUND(v0, v1, v2, v3);
	SIP_DOUBLE_ROUND(v0, v1, v2, v3);

	return (v0 ^ v1) ^ (v2 ^ v3);
}

