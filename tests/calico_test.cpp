#include <iostream>
#include <cassert>
#include <cstdlib>
#include <climits>
using namespace std;

#include "calico.h"
#include "Clock.hpp"
#include "AbyssinianPRNG.hpp"
#include "SecureEqual.hpp"
using namespace cat;

static Clock m_clock;

typedef void (*TestFunction)();

/*
 * Verify that the code reacts properly when used without a key
 */
void UninitializedTest() {
	calico_state S;

	CAT_OBJCLR(S);

	char overhead[CALICO_DATAGRAM_OVERHEAD];
	char data[10] = {0};
	int bytes = (int)sizeof(data);

	// Assert that the encryption function fails if it is unkeyed
	assert(calico_encrypt(&S, data, data, bytes, overhead, sizeof(overhead)));

	// Assert that the decryption function fails if it is unkeyed
	assert(calico_decrypt(&S, data, bytes, overhead, sizeof(overhead)));
}

/*
 * Check that data may be sent over the tunnel without getting corrupted
 */
void DataIntegrityTest() {
	// Client and server states and room for encrypted data
	calico_state c, s;
	char orig_data[10000], enc_data[10000 + 1];
	char overhead[CALICO_DATAGRAM_OVERHEAD];

	char key[32] = {0};

	{
		assert(!calico_key(&c, sizeof(c), CALICO_INITIATOR, key, sizeof(key)));
		assert(!calico_key(&s, sizeof(s), CALICO_RESPONDER, key, sizeof(key)));

		// Verify that calico encrypt function checks negative length
		assert(calico_encrypt(&c, enc_data, enc_data, -1, overhead, sizeof(overhead)));

		// NULL pointer checks
		assert(calico_encrypt(&c, 0, enc_data, 100, overhead, sizeof(overhead)));
		assert(calico_encrypt(0, enc_data, enc_data, 100, overhead, sizeof(overhead)));
		assert(calico_encrypt(&c, enc_data, 0, 100, overhead, sizeof(overhead)));
		assert(calico_encrypt(&c, enc_data, enc_data, 100, 0, sizeof(overhead)));

		for (int ii = 0; ii < sizeof(orig_data); ++ii) {
			orig_data[ii] = ii;
		}

		for (int len = 0; len < 10000; ++len) {
			enc_data[len] = 'A';

			assert(!calico_encrypt(&c, enc_data, orig_data, len, overhead, sizeof(overhead)));
			assert(!calico_decrypt(&s, enc_data, len, overhead, sizeof(overhead)));

			assert(SecureEqual(enc_data, orig_data, len));

			assert(enc_data[len] == 'A');
		}
	}
}

/*
 * Test where each side is using a different key
 */
void WrongKeyTest() {
	char xkey[32] = {0};
	char ykey[32] = {1};

	calico_state x, y;
	char data[32] = {0};
	char overhead[CALICO_DATAGRAM_OVERHEAD];

	assert(!calico_key(&x, sizeof(x), CALICO_INITIATOR, xkey, sizeof(xkey)));
	assert(!calico_encrypt(&x, data, data, 32, overhead, sizeof(overhead)));

	// Verify that it cannot be decrypted when the wrong key is used
	assert(!calico_key(&y, sizeof(y), CALICO_RESPONDER, ykey, sizeof(ykey)));
	assert(calico_decrypt(&y, data, 32, overhead, sizeof(overhead)));

	// Verify that it can be decrypted when the right key is used
	assert(!calico_key(&y, sizeof(y), CALICO_RESPONDER, xkey, sizeof(xkey)));
	assert(!calico_decrypt(&y, data, 32, overhead, sizeof(overhead)));
}

/*
 * Test replay attack defense
 */
void ReplayAttackTest() {
	char key[32] = {0};

	calico_state x, y;
	assert(!calico_key(&x, sizeof(x), CALICO_INITIATOR, key, sizeof(key)));
	assert(!calico_key(&y, sizeof(y), CALICO_RESPONDER, key, sizeof(key)));

	char data[32] = {0};
	char overhead[CALICO_DATAGRAM_OVERHEAD];

	assert(!calico_encrypt(&x, data, data, 32, overhead, sizeof(overhead)));

	assert(!calico_decrypt(&y, data, 32, overhead, sizeof(overhead)));

	// Re-use IV 0

	assert(!calico_key(&x, sizeof(x), CALICO_INITIATOR, key, sizeof(key)));

	assert(!calico_encrypt(&x, data, data, 32, overhead, sizeof(overhead)));

	// Decryption should fail here since IV was reused
	assert(calico_decrypt(&y, data, 32, overhead, sizeof(overhead)));

	// Continue with IV 1

	assert(!calico_encrypt(&x, data, data, 32, overhead, sizeof(overhead)));

	assert(!calico_decrypt(&y, data, 32, overhead, sizeof(overhead)));
}

/*
 * Verify that packets can be received out of order up to a certain distance
 */
void ReplayWindowTest() {
	char key[32] = {0};

	calico_state x, y;

	assert(!calico_key(&x, sizeof(x), CALICO_INITIATOR, key, sizeof(key)));
	assert(!calico_key(&y, sizeof(y), CALICO_RESPONDER, key, sizeof(key)));

	char data[32] = {0};
	char overhead[CALICO_DATAGRAM_OVERHEAD];

	// Advance IV for x by 2048 (simulate dropping lots of packets)
	for (int ii = 0; ii < 2048; ++ii) {
		assert(!calico_encrypt(&x, data, data, 32, overhead, sizeof(overhead)));
	}

	// Deliver the last one
	assert(!calico_decrypt(&y, data, 32, overhead, sizeof(overhead)));

	// Now replay them all

	assert(!calico_key(&x, sizeof(x), CALICO_INITIATOR, key, sizeof(key)));

	for (int ii = 0; ii < 1024; ++ii) {
		assert(!calico_encrypt(&x, data, data, 32, overhead, sizeof(overhead)));

		// Verify IV drop
		assert(calico_decrypt(&y, data, 32, overhead, sizeof(overhead)));
	}

	for (int ii = 1024; ii < 2047; ++ii) {
		assert(!calico_encrypt(&x, data, data, 32, overhead, sizeof(overhead)));

		assert(!calico_decrypt(&y, data, 32, overhead, sizeof(overhead)));
	}

	// Test replay of original packet

	assert(!calico_encrypt(&x, data, data, 32, overhead, sizeof(overhead)));

	// Verify that replay is dropped
	assert(calico_decrypt(&y, data, 32, overhead, sizeof(overhead)));

	// Test some forward movement

	for (int ii = 0; ii < 1024; ++ii) {
		assert(!calico_encrypt(&x, data, data, 32, overhead, sizeof(overhead)));

		assert(!calico_decrypt(&y, data, 32, overhead, sizeof(overhead)));
	}
}

/*
 * Test performance of Initialize() function
 */
void BenchmarkInitialize() {
	char key[32] = {0};

	double t0 = m_clock.usec();

	for (int ii = 0; ii < 100000; ++ii) {
		key[ii % 32] += 37;

		calico_state x;

		assert(!calico_key(&x, sizeof(x), CALICO_INITIATOR, key, sizeof(key)));
	}

	double t1 = m_clock.usec();

	double adt = (t1 - t0) / 100000.0;

	double fps = 1000000.0 / adt;

	cout << "Benchmark: Initialize() in " << adt << " usec on average / " << fps << " per second" << endl;
}

/*
 * Test performance of Encrypt() function
 */
void BenchmarkEncrypt() {
	char key[32] = {0};
	calico_state x;

	assert(!calico_key(&x, sizeof(x), CALICO_INITIATOR, key, sizeof(key)));

	char orig[10000] = {0};
	char data[10000] = {0};
	char overhead[CALICO_DATAGRAM_OVERHEAD];

	for (int bytes = 10000; bytes > 0; bytes /= 10) {
		double t0 = m_clock.usec();

		for (int ii = 0; ii < 100000; ++ii) {
			assert(!calico_encrypt(&x, data, orig, bytes, overhead, sizeof(overhead)));
		}

		double t1 = m_clock.usec();

		double adt = (t1 - t0) / 100000.0;

		double fps = 1000000.0 / adt;

		double mbps = bytes * fps / 1000000.0;

		cout << "calico_datagram_encrypt: " << bytes << " bytes in " << adt << " usec on average / " << mbps << " MBPS / " << fps << " per second" << endl;
	}
}

/*
 * Test performance of Decrypt() function when it fails
 */
void BenchmarkDecryptFail() {
	char key[32] = {0};
	calico_state x, y;

	assert(!calico_key(&x, sizeof(x), CALICO_INITIATOR, key, sizeof(key)));
	assert(!calico_key(&y, sizeof(y), CALICO_RESPONDER, key, sizeof(key)));

	char data[10000] = {0};
	char overhead[CALICO_DATAGRAM_OVERHEAD];

	for (int bytes = 10000; bytes > 0; bytes /= 10) {
		assert(!calico_encrypt(&x, data, data, bytes, overhead, sizeof(overhead)));

		data[0] ^= 1;

		double t0 = m_clock.usec();

		for (int ii = 0; ii < 100000; ++ii) {
			assert(calico_decrypt(&y, data, bytes, overhead, sizeof(overhead)));
		}

		double t1 = m_clock.usec();

		double adt = (t1 - t0) / 100000.0;

		double fps = 1000000.0 / adt;

		double mbps = bytes * fps / 1000000.0;

		cout << "calico_datagram_decrypt: drops " << bytes << " corrupted bytes in " << adt << " usec on average / " << mbps << " MBPS / " << fps << " per second" << endl;
	}
}

/*
 * Test performance of Decrypt() function when it succeeds
 */
void BenchmarkDecryptSuccess() {
	char key[32] = {0};
	calico_state x, y;

	assert(!calico_key(&x, sizeof(x), CALICO_INITIATOR, key, sizeof(key)));
	assert(!calico_key(&y, sizeof(y), CALICO_RESPONDER, key, sizeof(key)));

	char data[10000];
	char temp[sizeof(data)];
	char overhead[CALICO_DATAGRAM_OVERHEAD];

	Abyssinian prng;
	prng.Initialize(m_clock.msec(), Clock::cycles());

	for (int bytes = 10000; bytes > 0; bytes /= 10) {
		double t_sum = 0;

		u32 *data_ptr = reinterpret_cast<u32*>( temp );
		for (int jj = 0; jj < (bytes + 3) / 4; ++jj) {
			data_ptr[jj] = prng.Next();
		}

		for (int ii = 0; ii < 100000; ++ii) {
			assert(!calico_encrypt(&x, data, temp, bytes, overhead, sizeof(overhead)));

			double t0 = m_clock.usec();

			assert(!calico_decrypt(&y, data, bytes, overhead, sizeof(overhead)));

			double t1 = m_clock.usec();

			assert(SecureEqual(data, temp, bytes));

			t_sum += t1 - t0;
		}

		double adt = t_sum / 100000.0;

		double fps = 1000000.0 / adt;

		double mbps = bytes * fps / 1000000.0;

		cout << "calico_datagram_decrypt: " << bytes << " bytes in " << adt << " usec on average / " << mbps << " MBPS / " << fps << " per second" << endl;
	}
}

/*
 * Test to ensure that the MAC includes the IV
 *
 * The first 3 bytes of overhead are assumed to be the IV for this test
 *
 * I verified that if the last parameter to siphash24() that is currently
 * the IV is set to 0 instead, then it will fail this test.
 */
void ReplayMACTest() {
	char key[32] = {0};

	static const u32 IV_FUZZ = 0x286AD7;

	calico_state x, y;
	char data_iv0[32] = {0};
	char overhead_iv0[CALICO_DATAGRAM_OVERHEAD];
	char data_iv1[32] = {1};
	char overhead_iv1[CALICO_DATAGRAM_OVERHEAD];
	char plaintext[32];
	char overhead_iv_mod[CALICO_DATAGRAM_OVERHEAD];

	assert(!calico_key(&x, sizeof(x), CALICO_INITIATOR, key, sizeof(key)));
	assert(!calico_key(&y, sizeof(y), CALICO_RESPONDER, key, sizeof(key)));

	assert(!calico_encrypt(&x, data_iv0, data_iv0, 32, overhead_iv0, sizeof(overhead_iv0)));
	assert(!calico_encrypt(&x, data_iv1, data_iv1, 32, overhead_iv1, sizeof(overhead_iv1)));

	memcpy(plaintext, data_iv0, 32);
	assert(!calico_decrypt(&y, plaintext, 32, overhead_iv0, sizeof(overhead_iv0)));

	// Use IV = 1, but keep the MAC the same as for IV = 0

	memcpy(overhead_iv_mod, overhead_iv0, sizeof(overhead_iv_mod));

	const u64 tag = *(u64*)(overhead_iv_mod + 3);
	const u32 iv = 1;

	// Obfuscate the truncated IV
	u32 trunc_iv = iv;
	trunc_iv -= (u32)tag;
	trunc_iv ^= IV_FUZZ;

	// Store IV and tag
	overhead_iv_mod[0] = (u8)trunc_iv;
	overhead_iv_mod[1] = (u8)(trunc_iv >> 16);
	overhead_iv_mod[2] = (u8)(trunc_iv >> 8);

	assert(calico_decrypt(&y, data_iv0, 32, overhead_iv_mod, sizeof(overhead_iv_mod)));
}

/*
 * Use stream API
 */
void StreamModeTest() {
	char data[10000];
	char orig[10000];
	char overhead[CALICO_STREAM_OVERHEAD];

	Abyssinian prng;
	prng.Initialize(m_clock.msec(), Clock::cycles());

	for (int ii = 0; ii < 10; ++ii) {
		u32 key[8];

		for (int jj = 0; jj < 8; ++jj) {
			key[jj] = prng.Next();
		}

		calico_stream_only x, y;

		assert(!calico_key(&x, sizeof(x), CALICO_INITIATOR, key, sizeof(key)));
		assert(!calico_key(&y, sizeof(y), CALICO_RESPONDER, key, sizeof(key)));

		u32 *data_ptr = reinterpret_cast<u32*>( orig );

		for (int messages = 0; messages < 100; ++messages) {
			// Send x -> y

			int len = prng.Next() % 10000;

			for (int jj = 0; jj < (len + 3) / 4; ++jj) {
				data_ptr[jj] = prng.Next();
			}

			assert(!calico_encrypt(&x, data, orig, len, overhead, sizeof(overhead)));
			assert(calico_encrypt((calico_state*)&x, data, orig, len, overhead, CALICO_DATAGRAM_OVERHEAD));

			assert(!calico_decrypt(&y, data, len, overhead, sizeof(overhead)));
			assert(SecureEqual(data, orig, len));

			// Send y -> x

			len = prng.Next() % 10000;

			for (int jj = 0; jj < (len + 3) / 4; ++jj) {
				data_ptr[jj] = prng.Next();
			}

			assert(!calico_encrypt(&y, data, orig, len, overhead, sizeof(overhead)));
			assert(calico_encrypt((calico_state*)&y, data, orig, len, overhead, CALICO_DATAGRAM_OVERHEAD));

			assert(!calico_decrypt(&x, data, len, overhead, sizeof(overhead)));
			assert(SecureEqual(data, orig, len));
		}
	}
}

/*
 * Run a lot of random input
 */
void StressTest() {
	char data[10000];
	char orig[10000];
	char overhead[CALICO_DATAGRAM_OVERHEAD];

	Abyssinian prng;
	prng.Initialize(m_clock.msec(), Clock::cycles());

	for (int ii = 0; ii < 1000; ++ii) {
		u32 key[8];

		for (int jj = 0; jj < 8; ++jj) {
			key[jj] = prng.Next();
		}

		calico_state x, y;

		assert(!calico_key(&x, sizeof(x), CALICO_INITIATOR, key, sizeof(key)));
		assert(!calico_key(&y, sizeof(y), CALICO_RESPONDER, key, sizeof(key)));

		u32 *data_ptr = reinterpret_cast<u32*>( orig );

		for (int messages = 0; messages < 1000; ++messages) {
			// Send x -> y

			int len = prng.Next() % 10000;

			for (int jj = 0; jj < (len + 3) / 4; ++jj) {
				data_ptr[jj] = prng.Next();
			}

			assert(!calico_encrypt(&x, data, orig, len, overhead, sizeof(overhead)));

			// Add 5% packetloss
			if (prng.Next() % 100 >= 5) {
				assert(!calico_decrypt(&y, data, len, overhead, sizeof(overhead)));
				assert(SecureEqual(data, orig, len));
			}

			// Send y -> x

			len = prng.Next() % 10000;

			for (int jj = 0; jj < (len + 3) / 4; ++jj) {
				data_ptr[jj] = prng.Next();
			}

			assert(!calico_encrypt(&y, data, orig, len, overhead, sizeof(overhead)));

			// Add 5% packetloss
			if (prng.Next() % 100 >= 5) {
				assert(!calico_decrypt(&x, data, len, overhead, sizeof(overhead)));
				assert(SecureEqual(data, orig, len));
			}
		}
	}
}

struct TestDescriptor
{
	TestFunction function;
	const char *description;
};

TestDescriptor TEST_FUNCTIONS[] = {
	// Tests to run:

	{ UninitializedTest, "Uninitialized" },

	{ DataIntegrityTest, "Data Integrity" },
	{ StreamModeTest, "Stream API Test" },

	{ WrongKeyTest, "Wrong Key" },
	{ ReplayAttackTest, "Replay Attack" },
	{ ReplayWindowTest, "Replay Window" },
	{ ReplayMACTest, "Replay MAC+Ciphertext with new IV test" },

	{ BenchmarkInitialize, "Benchmark Initialize()" },
	{ BenchmarkEncrypt, "Benchmark Encrypt()" },
	{ BenchmarkDecryptFail, "Benchmark Decrypt() Rejection" },
	{ BenchmarkDecryptSuccess, "Benchmark Decrypt() Accept" },

	{ StressTest, "2 Million Random Message Stress Test" },

	{ 0, 0 } // End of tests
};

int main()
{
	int index = 0;
	int failures = 0, passes = 0, tests = 0;

	m_clock.OnInitialize();

	// Always initialize Calico and check its return value
	// Note that using assertions in production code is a bad idea because on
	// some platforms assert() is not compiled and the code will never run.

	assert(!calico_init());

	for (TestDescriptor *td = TEST_FUNCTIONS; td->function; ++td, ++index)
	{
		cout << "Running test " << index << " : " << td->description << endl;

		++tests;

		try
		{
			td->function();

			cout << "+++ Test passed." << endl << endl;

			passes++;
		}
		catch (const char *err)
		{
			cout << "--- Test failed: " << err << endl << endl;

			failures++;
		}
	}

	cout << endl << "Test summary:" << endl;
	cout << "Passed " << passes << " tests of " << tests << endl;

	m_clock.OnFinalize();

	if (failures != 0)
	{
		cout << endl << "FAILURE: " << failures << " of " << tests << " tests did NOT pass!" << endl;
		return 1;
	}
	else
	{
		cout << endl << "All tests passed." << endl;
		return 0;
	}
}

