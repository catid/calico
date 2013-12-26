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

#ifndef CAT_CALICO_H
#define CAT_CALICO_H

#ifdef __cplusplus
extern "C" {
#endif

#define CALICO_VERSION 1

/*
 * Verify binary compatibility with the Calico API on startup.
 *
 * Example:
 * 	if (calico_init()) throw "Update calico static library";
 *
 * Returns 0 on success.
 * Returns non-zero if the API level does not match.
 */
extern int _calico_init(int expected_version);
#define calico_init() _calico_init(CALICO_VERSION)

typedef struct {
	char internal[160 + 160 + 8 + 8 + 128 + 32 + 32];
} calico_state;

enum CalicoRoles {
	CALICO_INITIATOR = 1,
	CALICO_RESPONDER = 2
};

enum CalicoOverhead {
	CALICO_OVERHEAD = 11 // Number of bytes added per message
};

/*
 * Initializes the calico_state object with a role and key
 *
 * Each side of the conversation needs to select a unique role.  If both sides
 * attempt to take on the same role, then the message contents may not be
 * protected.  The role is either CALICO_INITIATOR or CALICO_RESPONDER.
 *
 * The key should be at least 32 bytes long to provide a 256-bit key.  This key
 * is often generated by a key agreement protocol.  If multiple Calico sessions
 * are created, then each one must have a unique key.
 *
 * Preconditions:
 * 	role = CALICO_INITIATOR or CALICO_RESPONDER
 *
 * Returns 0 on success.
 * Returns non-zero if one of the input parameters is invalid.
 * It is important to check the return value to avoid active attacks.
 */
extern int calico_key(calico_state *S, int role, const char key[32]);

/*
 * Encrypt plaintext into ciphertext
 *
 * The plaintext buffer should contain the message to encrypt.  The result will
 * be written to the ciphertext buffer, which may overlap with the plaintext
 * buffer.  After encryption, the ciphertext_bytes will be set to the size of
 * the encrypted message.
 *
 * Preconditions:
 *	*ciphertext_bytes >= CALICO_OVERHEAD + plaintext_bytes
 *
 * Returns 0 on success.
 * Returns non-zero if one of the input parameters is invalid.
 * It is important to check the return value to avoid active attacks.
 */
extern int calico_encrypt(calico_state *S, const void *plaintext, int plaintext_bytes, void *ciphertext, int *ciphertext_bytes);

/*
 * Decrypt ciphertext into plaintext
 *
 * The ciphertext is decrypted in-place.  The provided ciphertext_bytes will be
 * set to the size of the plaintext after decryption.
 *
 * Preconditions:
 *	*ciphertext_bytes > CALICO_OVERHEAD
 *
 * Returns 0 on success.
 * Returns non-zero if one of the input parameters is invalid.
 * It is important to check the return value to avoid active attacks.
 */
extern int calico_decrypt(calico_state *S, void *ciphertext, int *ciphertext_bytes);

/*
 * Clean up a calico_state object
 *
 * The purpose of cleaning up the object is to securely erase the internal
 * state of the Calico session.
 */
extern void calico_cleanup(calico_state *S);


#ifdef __cplusplus
}
#endif


#endif // CAT_CALICO_H

