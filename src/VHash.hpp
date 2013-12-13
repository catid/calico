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

#ifndef CAT_VHASH_HPP
#define CAT_VHASH_HPP

#include "Platform.hpp"

/*
	Mostly copied from the original VHASH implementation
	by Ted Krovetz (tdk@acm.org) and Wei Dai from 17 APR 08, 1700 PDT

	References:

	http://eprint.iacr.org/2007/338.pdf
	http://www.fastcrypto.org/vmac/draft-krovetz-vmac-01.txt
*/

namespace cat {


// VHash internal state
typedef struct {
	static const int BYTES = 128;
	static const int WORDS = BYTES / 8; // 16

	u64 nhkey[WORDS];
	u64 polykey[2];
	u64 l3key[2];
} vhash_state;

/*
 * Initialize the VHash session
 *
 * The state should already be filled with 160 bytes of key material
 *
 * This function will handle tweaking the input to work as a VHash state
 *
 * When done with the vhash_state object, it should be securely erased
 */
void vhash_set_key(vhash_state *S);

/*
 * Hashes the given data with the current VHash state
 */
u64 vhash(vhash_state *S, const void *data, int bytes);


} // namespace cat

#endif // CAT_VHASH_HPP

