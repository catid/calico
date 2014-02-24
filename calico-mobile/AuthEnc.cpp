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

#include "AuthEnc.hpp"
#include "SipHash.hpp"
#include "EndianNeutral.hpp"
using namespace cat;

#include "chacha.h"

#ifndef CAT_CHACHA_IMPL
#define chacha_blocks_impl chacha_blocks_ref
#endif

// Using the internal chacha_blocks() function to speed up invalid message rejection
extern "C" void chacha_blocks_impl(chacha_state_t *state, const uint8_t *in, uint8_t *out, size_t bytes);

bool cat::auth_key_expand(const char key[32], void *buffer, int bytes)
{
	if (bytes % 64) {
		return false;
	}

	chacha_iv iv = {{ 0 }};

	chacha((const chacha_key *)key, &iv, 0, (u8 *)buffer, bytes, 20);

	return true;
}

u64 cat::auth_encrypt(auth_enc_state *state, const char key[48],
					  u64 iv_counter, const void *from, void *to, int bytes)
{
	const u64 iv = getLE64(iv_counter);

	// Setup the cipher with the key and IV
	chacha_state S;
	chacha_init(&S, (const chacha_key *)key, (const chacha_iv *)&iv, 14);

	// Encrypt data
	chacha_blocks_impl(&S, (const u8 *)from, (u8 *)to, bytes);

	// Generate MAC tag
	return siphash24(key + 32, to, bytes);
}

bool cat::auth_decrypt(auth_enc_state *state, const char key[48],
					   u64 iv_counter, void *buffer, int bytes, u64 provided_tag)
{
	const u64 iv = getLE64(iv_counter);

	// Setup the cipher with the key and IV
	chacha_state S;
	chacha_init(&S, (const chacha_key *)key, (const chacha_iv *)&iv, 14);

	// Generate expected MAC tag
	const u64 expected_tag = siphash24(key + 32, buffer, bytes);

	// Verify MAC tag in constant-time
	const u64 delta = expected_tag ^ provided_tag;
	const u32 z = (u32)(delta >> 32) | (u32)delta;
	if (z) {
		return false;
	}

	// Decrypt data
	chacha_blocks_impl(&S, (const u8 *)buffer, (u8 *)buffer, bytes);

	return true;
}

