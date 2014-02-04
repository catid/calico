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

#ifndef CAT_CALICO_H
#define CAT_CALICO_H

/*
 * None of these functions are thread-safe.
 */

#ifdef __cplusplus
extern "C" {
#endif

#define CALICO_VERSION 5

/*
 * Verify binary compatibility with the Calico API on startup.
 *
 * Example:
 * 	if (calico_init()) {
 * 		// The calico static library needs to be updated
 * 		exit(1);
 * 	}
 *
 * Returns 0 on success.
 * Returns non-zero if the API level does not match.
 */
extern int _calico_init(int expected_version);
#define calico_init() _calico_init(CALICO_VERSION)


typedef struct {
	char internal[480];
} calico_stream_only;

typedef struct {
	char internal[620];
} calico_state;


enum CalicoRoles {
	CALICO_INITIATOR = 1,
	CALICO_RESPONDER = 2
};

enum CalicoOverhead {
	CALICO_DATAGRAM_OVERHEAD = 11, // Number of bytes added per datagram message
	CALICO_STREAM_OVERHEAD = 8 // Number of bytes added per stream message
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
 * After keying the Calico state object, it may be used to encrypt or decrypt
 * messages.  Both datagram and stream mode may be used from the same object.
 * It is important to only call calico_key() once per key.  Do not use separate
 * calico_state objects to transmit and to receive data.
 *
 * When finished with the Calico state object, call calico_cleanup().
 *
 * Preconditions:
 * 	key_bytes = 32
 * 	key = Valid pointer to 32 bytes of unique key material
 * 	role = CALICO_INITIATOR or CALICO_RESPONDER
 *
 * Returns 0 on success.
 * Returns non-zero if one of the input parameters is invalid.
 * It is important to check the return value to avoid active attacks.
 */
extern int calico_key(calico_state *S, int role, const void *key, int key_bytes);

/*
 * To cut the amount of memory required for encryption in half, a TCP-stream-
 * only mode is also offered.
 */
extern int calico_key_stream_only(calico_stream_only *S, int role, const void *key, int key_bytes);

/*
 * Encrypt plaintext into ciphertext for datagram transport
 *
 * UDP-based protocols work with this type of encryption.
 *
 * The plaintext buffer should contain the message to encrypt.  The ciphertext
 * buffer will be set to the encrypted message, which is the same size as the
 * plaintext buffer, and may also be done in-place.
 *
 * Transmit the overhead buffer along with the ciphertext.
 *
 * Preconditions:
 * 	overhead buffer contains CALICO_DATAGRAM_OVERHEAD bytes
 *
 * Returns 0 on success.
 * Returns non-zero if one of the input parameters is invalid.
 * It is important to check the return value to avoid active attacks.
 */
extern int calico_datagram_encrypt(calico_state *S, void *ciphertext, const void *plaintext, int bytes, void *overhead);

/*
 * Decrypt ciphertext into plaintext from datagram transport
 *
 * UDP-based protocols work with this type of encryption.
 *
 * The ciphertext is decrypted in-place.
 *
 * Preconditions:
 *	overhead buffer contains CALICO_DATAGRAM_OVERHEAD bytes
 *
 * Returns 0 on success.
 * Returns non-zero if one of the input parameters is invalid.
 * It is important to check the return value to avoid active attacks.
 */
extern int calico_datagram_decrypt(calico_state *S, void *ciphertext, int bytes, const void *overhead);

/*
 * Encrypt plaintext into ciphertext for stream transport
 *
 * This function accepts either a calico_state or calico_stream_only object.
 *
 * TCP-based protocols work best with this type of encryption.
 *
 * The plaintext buffer should contain the message to encrypt.  The ciphertext
 * buffer will be set to the encrypted message, which is the same size as the
 * plaintext buffer, and may also be done in-place.
 *
 * Transmit the overhead buffer along with the ciphertext.
 *
 * Preconditions:
 * 	overhead buffer contains CALICO_STREAM_OVERHEAD bytes
 *
 * Returns 0 on success.
 * Returns non-zero if one of the input parameters is invalid.
 * It is important to check the return value to avoid active attacks.
 */
extern int calico_stream_encrypt(void *S, void *ciphertext, const void *plaintext, int bytes, void *overhead);

/*
 * Decrypt ciphertext into plaintext from stream transport
 *
 * TCP-based protocols work best with this type of encryption.
 *
 * The ciphertext is decrypted in-place.
 *
 * Preconditions:
 * 	overhead buffer contains CALICO_STREAM_OVERHEAD bytes
 *
 * Returns 0 on success.
 * Returns non-zero if one of the input parameters is invalid.
 * It is important to check the return value to avoid active attacks.
 */
extern int calico_stream_decrypt(void *S, void *ciphertext, int bytes, const void *overhead);

/*
 * Clean up a calico_state or calico_stream_only object
 *
 * The purpose of cleaning up the object is to securely erase the internal
 * state of the Calico session.
 */
extern void calico_cleanup(void *S);


#ifdef __cplusplus
}
#endif


#endif // CAT_CALICO_H

