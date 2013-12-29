#include <iostream>
#include <cassert>
#include <cstdlib>
using namespace std;

#include "calico.h"
#include "Clock.hpp"
#include "AbyssinianPRNG.hpp"
using namespace cat;

static Clock m_clock;

typedef void (*TestFunction)();

/*
 * Verify that the code reacts properly when used without a key
 *
 * Note that valgrind will complain about these but it is okay.
 */
void UninitializedTest()
{
	calico_state S;

	char data[10 + CALICO_DATAGRAM_OVERHEAD] = {0};
	int bytes = (int)sizeof(data);

	// Assert that the encryption function fails if it is unkeyed
	assert(calico_datagram_encrypt(&S, data, 10, data, &bytes));

	// Assert that the decryption function fails if it is unkeyed
	bytes = (int)sizeof(data);
	assert(calico_datagram_decrypt(&S, data, &bytes));
}

/*
 * Check that data may be sent over the tunnel without getting corrupted
 */
void DataIntegrityTest()
{
	// Client and server states and room for encrypted data
	calico_state c, s;
	char orig_data[10000], enc_data[10000 + CALICO_DATAGRAM_OVERHEAD + 1];

	char key[32] = {0};
	int bytes;

	{
		assert(!calico_key(&c, CALICO_INITIATOR, key, sizeof(key)));
		assert(!calico_key(&s, CALICO_RESPONDER, key, sizeof(key)));

		// Verify that calico encrypt function checks negative length
		bytes = (int)sizeof(enc_data);
		assert(calico_datagram_encrypt(&c, enc_data, -1, enc_data, &bytes));

		// Verify that calico encrypt function checks ciphertext buffer that is too small
		bytes = 101;
		assert(calico_datagram_encrypt(&c, enc_data, 100, enc_data, &bytes));

		// NULL pointer checks
		bytes = (int)sizeof(enc_data);
		assert(calico_datagram_encrypt(&c, 0, 100, enc_data, &bytes));
		bytes = (int)sizeof(enc_data);
		assert(calico_datagram_encrypt(&c, enc_data, 100, 0, &bytes));
		assert(calico_datagram_encrypt(&c, enc_data, 100, enc_data, 0));
		bytes = (int)sizeof(enc_data);
		assert(calico_datagram_encrypt(0, enc_data, 100, enc_data, &bytes));

		for (int ii = 0; ii < sizeof(orig_data); ++ii)
			orig_data[ii] = ii;

		for (int len = 0; len < 10000; ++len)
		{
			enc_data[len + CALICO_DATAGRAM_OVERHEAD] = 'A';

			int enclen = (int)sizeof(enc_data);
			assert(!calico_datagram_encrypt(&c, orig_data, len, enc_data, &enclen));
			assert(enclen == len + CALICO_DATAGRAM_OVERHEAD);

			int declen = enclen;
			assert(!calico_datagram_decrypt(&s, enc_data, &declen));
			assert(len == declen);

			assert(!memcmp(enc_data, orig_data, len));

			assert(enc_data[len + CALICO_DATAGRAM_OVERHEAD] == 'A');
		}
	}
}

/*
 * Test verifying that large integer input to the API will not cause crashes or other issues
 */
void IntOverflowTest()
{
	char xkey[32] = {0};
	char ykey[32] = {1};

	calico_state x, y;
	assert(!calico_key(&x, CALICO_INITIATOR, xkey, sizeof(xkey)));
	assert(!calico_key(&y, CALICO_RESPONDER, ykey, sizeof(ykey)));

	char data[32 + CALICO_DATAGRAM_OVERHEAD] = {0};

	for (int data_len = INT_MAX - CALICO_DATAGRAM_OVERHEAD + 1; data_len > 0; ++data_len) {
		int bytes = (int)sizeof(data);
		assert(calico_datagram_encrypt(&x, data, data_len, data, &bytes));
	}

	for (int data_len = INT_MIN; data_len < INT_MIN + CALICO_DATAGRAM_OVERHEAD + 1; ++data_len) {
		int bytes = (int)sizeof(data);
		assert(calico_datagram_encrypt(&x, data, data_len, data, &bytes));
	}

	for (int data_len = INT_MIN; data_len  < INT_MIN + CALICO_DATAGRAM_OVERHEAD + 10; ++data_len) {
		int bytes = data_len;
		assert(calico_datagram_decrypt(&y, data, &bytes));
	}
}

/*
 * Test where each side is using a different key
 */
void WrongKeyTest()
{
	char xkey[32] = {0};
	char ykey[32] = {1};

	calico_state x, y;
	char data[32 + CALICO_DATAGRAM_OVERHEAD] = {0};

	assert(!calico_key(&x, CALICO_INITIATOR, xkey, sizeof(xkey)));
	int bytes = (int)sizeof(data);
	assert(!calico_datagram_encrypt(&x, data, 32, data, &bytes));
	assert(bytes == sizeof(data));

	// Verify that it cannot be decrypted when the wrong key is used
	assert(!calico_key(&y, CALICO_RESPONDER, ykey, sizeof(ykey)));
	assert(bytes == sizeof(data));
	assert(calico_datagram_decrypt(&y, data, &bytes));

	// Verify that it can be decrypted when the right key is used
	assert(!calico_key(&y, CALICO_RESPONDER, xkey, sizeof(xkey)));
	assert(bytes == sizeof(data));
	assert(!calico_datagram_decrypt(&y, data, &bytes));
}

/*
 * Test replay attack defense
 */
void ReplayAttackTest()
{
	char key[32] = {0};

	calico_state x, y;
	assert(!calico_key(&x, CALICO_INITIATOR, key, sizeof(key)));
	assert(!calico_key(&y, CALICO_RESPONDER, key, sizeof(key)));

	char data[32 + CALICO_DATAGRAM_OVERHEAD] = {0};

	int bytes = (int)sizeof(data);
	assert(!calico_datagram_encrypt(&x, data, 32, data, &bytes));
	assert(bytes == sizeof(data));

	assert(!calico_datagram_decrypt(&y, data, &bytes));
	assert(bytes == 32);

	// Re-use IV 0

	assert(!calico_key(&x, CALICO_INITIATOR, key, sizeof(key)));

	bytes = (int)sizeof(data);
	assert(!calico_datagram_encrypt(&x, data, 32, data, &bytes));
	assert(bytes == sizeof(data));

	// Decryption should fail here since IV was reused
	assert(calico_datagram_decrypt(&y, data, &bytes));

	// Continue with IV 1

	bytes = (int)sizeof(data);
	assert(!calico_datagram_encrypt(&x, data, 32, data, &bytes));
	assert(bytes == sizeof(data));

	assert(!calico_datagram_decrypt(&y, data, &bytes));
	assert(bytes == 32);
}

/*
 * Verify that packets can be received out of order up to a certain distance
 */
void ReplayWindowTest()
{
	char key[32] = {0};

	calico_state x, y;

	assert(!calico_key(&x, CALICO_INITIATOR, key, sizeof(key)));
	assert(!calico_key(&y, CALICO_RESPONDER, key, sizeof(key)));

	char data[32 + CALICO_DATAGRAM_OVERHEAD] = {0};
	int bytes;

	// Advance IV for x by 2048 (simulate dropping lots of packets)
	for (int ii = 0; ii < 2048; ++ii)
	{
		bytes = (int)sizeof(data);
		assert(!calico_datagram_encrypt(&x, data, 32, data, &bytes));
		assert(bytes == sizeof(data));
	}

	// Deliver the last one
	assert(!calico_datagram_decrypt(&y, data, &bytes));
	assert(bytes == 32);

	// Now replay them all

	assert(!calico_key(&x, CALICO_INITIATOR, key, sizeof(key)));

	for (int ii = 0; ii < 1024; ++ii)
	{
		bytes = (int)sizeof(data);
		assert(!calico_datagram_encrypt(&x, data, 32, data, &bytes));
		assert(bytes == sizeof(data));

		// Verify IV drop
		assert(calico_datagram_decrypt(&y, data, &bytes));
	}

	for (int ii = 1024; ii < 2047; ++ii)
	{
		bytes = (int)sizeof(data);
		assert(!calico_datagram_encrypt(&x, data, 32, data, &bytes));
		assert(bytes == sizeof(data));

		assert(!calico_datagram_decrypt(&y, data, &bytes));
		assert(bytes == 32);
	}

	// Test replay of original packet

	bytes = (int)sizeof(data);
	assert(!calico_datagram_encrypt(&x, data, 32, data, &bytes));
	assert(bytes == sizeof(data));

	// Verify that replay is dropped
	assert(calico_datagram_decrypt(&y, data, &bytes));

	// Test some forward movement

	for (int ii = 0; ii < 1024; ++ii)
	{
		int bytes = (int)sizeof(data);
		assert(!calico_datagram_encrypt(&x, data, 32, data, &bytes));
		assert(bytes == sizeof(data));

		assert(!calico_datagram_decrypt(&y, data, &bytes));
		assert(bytes == 32);
	}
}

/*
 * Test performance of Initialize() function
 */
void BenchmarkInitialize()
{
	char key[32] = {0};

	double t0 = m_clock.usec();

	for (int ii = 0; ii < 100000; ++ii)
	{
		key[ii % 32] += 37;

		calico_state x;

		assert(!calico_key(&x, CALICO_INITIATOR, key, sizeof(key)));
	}

	double t1 = m_clock.usec();

	double adt = (t1 - t0) / 100000.0;

	double fps = 1000000.0 / adt;

	cout << "Benchmark: Initialize() in " << adt << " usec on average / " << fps << " per second" << endl;
}

/*
 * Test performance of Encrypt() function
 */
void BenchmarkEncrypt()
{
	char key[32] = {0};
	calico_state x;

	assert(!calico_key(&x, CALICO_INITIATOR, key, sizeof(key)));

	char orig[10000 + CALICO_DATAGRAM_OVERHEAD] = {0};
	char data[10000 + CALICO_DATAGRAM_OVERHEAD] = {0};

	for (int bytes = 10000; bytes > 0; bytes /= 10)
	{
		double t0 = m_clock.usec();

		for (int ii = 0; ii < 100000; ++ii)
		{
			int databytes = (int)sizeof(data);
			assert(!calico_datagram_encrypt(&x, orig, bytes, data, &databytes));
			assert(databytes == bytes + CALICO_DATAGRAM_OVERHEAD);
		}

		double t1 = m_clock.usec();

		double adt = (t1 - t0) / 100000.0;

		double fps = 1000000.0 / adt;

		double mbps = bytes * fps / 1000000.0;

		cout << "Benchmark: Encrypt() " << bytes << " bytes in " << adt << " usec on average / " << mbps << " MBPS / " << fps << " per second" << endl;
	}
}

/*
 * Test performance of Decrypt() function when it fails
 */
void BenchmarkDecryptFail()
{
	char key[32] = {0};
	calico_state x, y;

	assert(!calico_key(&x, CALICO_INITIATOR, key, sizeof(key)));
	assert(!calico_key(&y, CALICO_RESPONDER, key, sizeof(key)));

	char data[10000 + CALICO_DATAGRAM_OVERHEAD] = {0};

	for (int bytes = 10000; bytes > 0; bytes /= 10)
	{
		int databytes = (int)sizeof(data);
		assert(!calico_datagram_encrypt(&x, data, bytes, data, &databytes));
		assert(databytes == bytes + CALICO_DATAGRAM_OVERHEAD);

		data[0] ^= 1;

		double t0 = m_clock.usec();

		for (int ii = 0; ii < 100000; ++ii)
		{
			assert(calico_datagram_decrypt(&y, data, &databytes));
		}

		double t1 = m_clock.usec();

		double adt = (t1 - t0) / 100000.0;

		double fps = 1000000.0 / adt;

		double mbps = bytes * fps / 1000000.0;

		cout << "Benchmark: Decrypt() drops " << bytes << " corrupted bytes in " << adt << " usec on average / " << mbps << " MBPS / " << fps << " per second" << endl;
	}
}

/*
 * Test performance of Decrypt() function when it succeeds
 */
void BenchmarkDecryptSuccess()
{
	char key[32] = {0};
	calico_state x, y;

	assert(!calico_key(&x, CALICO_INITIATOR, key, sizeof(key)));
	assert(!calico_key(&y, CALICO_RESPONDER, key, sizeof(key)));

	char data[10000 + CALICO_DATAGRAM_OVERHEAD];
	char temp[sizeof(data)];

	Abyssinian prng;
	prng.Initialize(m_clock.msec(), Clock::cycles());

	for (int bytes = 10000; bytes > 0; bytes /= 10)
	{
		double t_sum = 0;

		u32 *data_ptr = reinterpret_cast<u32*>( temp );
		for (int jj = 0; jj < (bytes + 3) / 4; ++jj)
			data_ptr[jj] = prng.Next();

		for (int ii = 0; ii < 100000; ++ii)
		{
			int databytes = (int)sizeof(data);
			assert(!calico_datagram_encrypt(&x, temp, bytes, data, &databytes));
			assert(databytes == bytes + CALICO_DATAGRAM_OVERHEAD);

			double t0 = m_clock.usec();

			assert(!calico_datagram_decrypt(&y, data, &databytes));

			double t1 = m_clock.usec();

			assert(databytes == bytes);

			assert(!memcmp(data, temp, bytes));

			t_sum += t1 - t0;
		}

		double adt = t_sum / 100000.0;

		double fps = 1000000.0 / adt;

		double mbps = bytes * fps / 1000000.0;

		cout << "Benchmark: Decrypt() " << bytes << " bytes in " << adt << " usec on average / " << mbps << " MBPS / " << fps << " per second" << endl;
	}
}

/*
 * Run a lot of random input
 */
void StressTest()
{
	char data[10000 + CALICO_DATAGRAM_OVERHEAD];
	char orig[10000 + CALICO_DATAGRAM_OVERHEAD];

	Abyssinian prng;
	prng.Initialize(m_clock.msec(), Clock::cycles());

	for (int ii = 0; ii < 1000; ++ii)
	{
		u32 key[8];

		for (int jj = 0; jj < 8; ++jj)
			key[jj] = prng.Next();

		calico_state x, y;

		assert(!calico_key(&x, CALICO_INITIATOR, key, sizeof(key)));
		assert(!calico_key(&y, CALICO_RESPONDER, key, sizeof(key)));

		u32 *data_ptr = reinterpret_cast<u32*>( orig );

		for (int messages = 0; messages < 1000; ++messages)
		{
			// Send x -> y

			int len = prng.Next() % 10000;

			for (int jj = 0; jj < (len + 3) / 4; ++jj)
				data_ptr[jj] = prng.Next();

			int databytes = (int)sizeof(data);
			assert(!calico_datagram_encrypt(&x, orig, len, data, &databytes));
			assert(databytes == len + CALICO_DATAGRAM_OVERHEAD);

			// Add 5% packetloss
			if (prng.Next() % 100 >= 5)
			{
				assert(!calico_datagram_decrypt(&y, data, &databytes));
				assert(databytes == len);
				assert(!memcmp(data, orig, databytes));
			}

			// Send y -> x

			len = prng.Next() % 10000;

			for (int jj = 0; jj < (len + 3) / 4; ++jj)
				data_ptr[jj] = prng.Next();

			databytes = (int)sizeof(data);
			assert(!calico_datagram_encrypt(&y, orig, len, data, &databytes));
			assert(databytes == len + CALICO_DATAGRAM_OVERHEAD);

			// Add 5% packetloss
			if (prng.Next() % 100 >= 5)
			{
				assert(!calico_datagram_decrypt(&x, data, &databytes));
				assert(databytes == len);
				assert(!memcmp(data, orig, databytes));
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

	{ IntOverflowTest, "Integer Overflow Input" },

	{ WrongKeyTest, "Wrong Key" },
	{ ReplayAttackTest, "Replay Attack" },
	{ ReplayWindowTest, "Replay Window" },

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

