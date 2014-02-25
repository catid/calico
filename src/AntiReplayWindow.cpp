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

#include "AntiReplayWindow.hpp"
using namespace cat;

void cat::antireplay_init(antireplay_state *S)
{
	S->last_accepted_iv = 0;

	CAT_OBJCLR(S->bitmap);
}

bool cat::antireplay_check(antireplay_state *S, u64 remote_iv)
{
	// Check how far in the past this IV is
	int delta = (int)(S->last_accepted_iv - remote_iv);

	// If it is in the past,
	if (delta >= 0)
	{
		// Check if we have kept a record for this IV
		if (delta >= antireplay_state::BITMAP_BITS) return false;

		// If it was seen, abort
		const u64 mask = (u64)1 << (delta & 63);
		if (S->bitmap[delta >> 6] & mask) return false;
	}

	return true;
}

void cat::antireplay_accept(antireplay_state *S, u64 remote_iv)
{
	// Check how far in the past/future this IV is
	int delta = (int)(remote_iv - S->last_accepted_iv);
	u64 *bitmap = S->bitmap;

	// If it is in the future,
	if (delta > 0)
	{
		// If it would shift out everything we have seen,
		if (delta >= antireplay_state::BITMAP_BITS)
		{
			// Set low bit to 1 and all other bits to 0
			bitmap[0] = 1;
			CAT_CLR(&bitmap[1], sizeof(S->bitmap) - sizeof(u64));
		}
		else
		{
			const int word_shift = delta >> 6;
			const int bit_shift = delta & 63;

			// Shift replay window
			if (bit_shift > 0)
			{
				u64 last = bitmap[antireplay_state::BITMAP_WORDS - 1 - word_shift];
				for (int ii = antireplay_state::BITMAP_WORDS - 1; ii >= word_shift + 1; --ii)
				{
					u64 x = bitmap[ii - word_shift - 1];
					bitmap[ii] = (last << bit_shift) | (x >> (64 - bit_shift));
					last = x;
				}
				bitmap[word_shift] = last << bit_shift;
			}
			else
			{
				for (int ii = antireplay_state::BITMAP_WORDS - 1; ii >= word_shift; --ii)
					bitmap[ii] = bitmap[ii - word_shift];
			}

			// Zero the words we skipped
			for (int ii = 0; ii < word_shift; ++ii)
				bitmap[ii] = 0;

			// Set low bit for this IV
			bitmap[0] |= 1;
		}

		// Only update the IV if the MAC was valid and the new IV is in the future
		S->last_accepted_iv = remote_iv;
	}
	else // Process an out-of-order packet
	{
		delta = -delta;

		// Set the bit in the bitmap for this IV
		bitmap[delta >> 6] |= (u64)1 << (delta & 63);
	}
}

