/*
	Copyright (c) 2012 Christopher A. Taylor.  All rights reserved.

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

/*
    The ChaCha cipher is a symmetric stream cipher based on Salsa20.
    http://cr.yp.to/chacha.html

	This implementation is NOT thread-safe.
*/

#ifndef CAT_CHACHA_VMAC_HPP
#define CAT_CHACHA_VMAC_HPP

#include "VHash.hpp"

namespace cat {


static const int CHACHA_ROUNDS = 8; // Multiple of 2

#define CHACHA_QUARTERROUND(A,B,C,D)					\
	x[A] += x[B]; x[D] = CAT_ROL32(x[D] ^ x[A], 16);	\
	x[C] += x[D]; x[B] = CAT_ROL32(x[B] ^ x[C], 12);	\
	x[A] += x[B]; x[D] = CAT_ROL32(x[D] ^ x[A], 8);		\
	x[C] += x[D]; x[B] = CAT_ROL32(x[B] ^ x[C], 7);

// Mixing function
#define CHACHA_MIX()	\
	for (int round = CHACHA_ROUNDS; round > 0; round -= 2) \
	{										\
		CHACHA_QUARTERROUND(0, 4, 8,  12)	\
		CHACHA_QUARTERROUND(1, 5, 9,  13)	\
		CHACHA_QUARTERROUND(2, 6, 10, 14)	\
		CHACHA_QUARTERROUND(3, 7, 11, 15)	\
		CHACHA_QUARTERROUND(0, 5, 10, 15)	\
		CHACHA_QUARTERROUND(1, 6, 11, 12)	\
		CHACHA_QUARTERROUND(2, 7, 8,  13)	\
		CHACHA_QUARTERROUND(3, 4, 9,  14)	\
	}

// Copy state into registers
#define CHACHA_COPY(state)					\
	state[12] = (u32)block_counter;			\
	state[13] = (u32)(block_counter >> 32);	\
	state[14] = (u32)iv;					\
	state[15] = (u32)(iv >> 32);			\
	for (int ii = 0; ii < 16; ++ii)			\
		x[ii] = state[ii];


class CAT_EXPORT ChaChaVMAC
{
	u32 _e_state[16], _d_state[16];
	VHash _local_mac, _remote_mac;

public:
	~ChaChaVMAC();

	/*
	 * Initialize(key)
	 *
	 * lkey: Local key (192 bytes)
	 * rkey: Remote key (192 bytes)
	 *
	 * No input checking is performed by this function.
	 */
	void Initialize(const u8 lkey[192], const u8 rkey[192]);

	/*
	 * Encrypt(buffer, bytes)
	 *
	 * Encrypts the from buffer into the to buffer, adding a MAC to the end.
	 *
	 * iv: Message initialization vector (IV)
	 * from: Pointer to plaintext buffer
	 * to: Pointer to output encrypted data buffer
	 * bytes: The length of the plaintext message
	 *
	 * The buffer must have room for the additional 8 bytes, and no input
	 * checking is performed by this function.
	 */
	void Encrypt(u64 iv, const void *from, void *to, int bytes);

	/*
	 * valid = Decrypt(buffer, bytes)
	 *
	 * Decrypts the given buffer in-place, plucking the last 8 bytes off the
	 * end that were added during encryption.
	 *
	 * iv: Message initialization vector (IV)
	 * buffer: The message to decrypt in-place
	 * bytes: Number of bytes in the original plaintext message (not including
	 * the IV added by the encryption process, see above)
	 *
	 * Returns true if the MAC was valid, or false if tampering was detected.
	 *
	 * This function performs no input checking.
	 */
	bool Decrypt(u64 iv, void *buffer, int bytes);
};


} // namespace cat

#endif // CAT_CHACHA_VMAC_HPP
