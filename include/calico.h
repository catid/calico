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

#define CALICO_VERSION 0

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
	// TODO
	char internal[64];
} CalicoState;

enum CalicoRoles {
	CALICO_INITIATOR = 1,
	CALICO_RESPONDER = 2
};

enum CalicoOverhead {
	CALICO_OVERHEAD = 11 // Number of bytes added per message
};

/*
 * TODO
 */
extern int calico_set_role(CalicoState *S, int role, const void *key, int key_bytes, const void *name, int name_bytes);

/*
 * TODO
 */
extern int calico_encrypt(CalicoState *S, const void *plaintext, int plaintext_bytes, void *ciphertext, int *ciphertext_bytes);

/*
 * TODO
 */
extern int calico_decrypt(CalicoState *S, void *ciphertext, int *ciphertext_bytes);

/*
 * TODO
 */
extern int calico_cleanup(CalicoState *S);


#ifdef __cplusplus
}
#endif


#endif // CAT_CALICO_H

