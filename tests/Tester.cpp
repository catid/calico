#include <iostream>
using namespace std;

#include "Calico.hpp"
#include "Clock.hpp"
#include "AbyssinianPRNG.hpp"
using namespace cat;
using namespace calico;

static Clock m_clock;

typedef void (*TestFunction)();

/*
 * Verify that the code reacts properly when used uninitialized
 */
void UninitializedTest()
{
	Calico x;
	char data[10 + Calico::OVERHEAD] = {0};

	if (x.Encrypt(data, 10, data, (int)sizeof(data)) != ERR_BAD_STATE)
		throw "Encrypt: Did not get bad state";

	if (x.Decrypt(data, (int)sizeof(data)) != ERR_BAD_STATE)
		throw "Decrypt: Did not get bad state";
}

/*
 * Check that data may be sent over the tunnel without getting corrupted
 */
void DataIntegrityTest()
{
	Calico x, y;
	char orig_data[10000], enc_data[10000 + Calico::OVERHEAD + 1];

	char key[32] = {0};
	const char *session_name = "Data Integrity Test";
	int r;

	{
		if (x.Initialize(key, session_name, INITIATOR) != ERR_GROOVY)
			throw "x.Initialize PACKET failed";
		if (y.Initialize(key, session_name, RESPONDER) != ERR_GROOVY)
			throw "y.Initialize PACKET failed";

		if (x.Encrypt(enc_data, -1, enc_data, (int)sizeof(enc_data)) != ERR_BAD_INPUT)
			throw "Does not check negative length";

		if (x.Encrypt(enc_data, 100, enc_data, 101) != ERR_TOO_SMALL)
			throw "Does not check max length";

		if (x.Encrypt(0, 100, enc_data, sizeof(enc_data)) != ERR_BAD_INPUT)
			throw "Does not check null pointer";

		if (x.Encrypt(enc_data, 100, 0, sizeof(enc_data)) != ERR_BAD_INPUT)
			throw "Does not check null pointer";

		for (int ii = 0; ii < sizeof(orig_data); ++ii)
			orig_data[ii] = ii;

		for (int len = 0; len < 10000; ++len)
		{
			enc_data[len + Calico::OVERHEAD] = 'A';

			int enclen = x.Encrypt(orig_data, len, enc_data, (int)sizeof(enc_data));

			if (enclen < 0)
				throw "Encryption failed";

			if (enclen != len + Calico::OVERHEAD)
				throw "Encrypted length is wrong";

			int declen = y.Decrypt(enc_data, enclen);

			if (declen < 0)
			{
				cerr << "Failure length " << len << endl;
				throw Calico::GetErrorString(declen);
			}

			if (declen != len)
				throw "Decrypted length is wrong";

			if (0 != memcmp(enc_data, orig_data, len))
				throw "Decrypted data does not match original data";

			if (enc_data[len + Calico::OVERHEAD] != 'A')
				throw "Corrupted past end of buffer";
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

	Calico x, y;

	if (x.Initialize(xkey, "Integer Overflow", INITIATOR) != ERR_GROOVY)
		throw "Unable to initialize x";

	if (y.Initialize(ykey, "Integer Overflow", RESPONDER) != ERR_GROOVY)
		throw "Unable to initialize y";

	char data[32 + Calico::OVERHEAD] = {0};

	for (int data_len = INT_MAX - Calico::OVERHEAD + 1; data_len > 0; ++data_len) {
		if (x.Encrypt(data, data_len, data, (int)sizeof(data)) != ERR_TOO_SMALL)
			throw "Encrypt did not reject bad integer input";
	}

	for (int data_len = INT_MIN; data_len < INT_MIN + Calico::OVERHEAD + 1; ++data_len) {
		if (x.Encrypt(data, data_len, data, (int)sizeof(data)) != ERR_BAD_INPUT)
			throw "Encrypt did not reject bad integer input";
	}

	for (int data_len = INT_MIN; data_len  < INT_MIN + Calico::OVERHEAD + 10; ++data_len) {
		if (x.Decrypt(data, data_len) != ERR_TOO_SMALL)
			throw "Decrypt did not reject bad integer input";
	}
}

/*
 * Test where each side is using a different key
 */
void WrongKeyTest()
{
	char xkey[32] = {0};
	char ykey[32] = {1};

	Calico x, y;

	if (x.Initialize(xkey, "Wrong Key", INITIATOR) != ERR_GROOVY)
		throw "Unable to initialize x";

	if (y.Initialize(ykey, "Wrong Key", RESPONDER) != ERR_GROOVY)
		throw "Unable to initialize y";

	char data[32 + Calico::OVERHEAD] = {0};

	if (x.Encrypt(data, 32, data, (int)sizeof(data)) != sizeof(data))
		throw "Encryption failed";

	int r = y.Decrypt(data, (int)sizeof(data));

	if (r != ERR_MAC_DROP && r != ERR_IV_DROP)
	{
		cerr << "Decrypt return value: " << Calico::GetErrorString(r) << endl;
		throw "Did not drop due to MAC/IV failure!";
	}
}

/*
 * Test replay attack defense
 */
void ReplayAttackTest()
{
	char key[32] = {0};

	Calico x, y;

	if (x.Initialize(key, "Replay Test", INITIATOR) != ERR_GROOVY)
		throw "Unable to initialize x";

	if (y.Initialize(key, "Replay Test", RESPONDER) != ERR_GROOVY)
		throw "Unable to initialize y";

	char data[32 + Calico::OVERHEAD] = {0};

	if (x.Encrypt(data, 32, data, (int)sizeof(data)) != sizeof(data))
		throw "Encryption failed";

	if (y.Decrypt(data, (int)sizeof(data)) != 32)
		throw "Decryption failed";

	// Re-use IV 0

	if (x.Initialize(key, "Replay Test", INITIATOR) != ERR_GROOVY)
		throw "Unable to initialize x(2)";

	if (x.Encrypt(data, 32, data, (int)sizeof(data)) != sizeof(data))
		throw "Encryption failed(2)";

	if (y.Decrypt(data, (int)sizeof(data)) != ERR_IV_DROP)
		throw "Did not catch replay attack for IV 0";

	// Continue with IV 1

	if (x.Encrypt(data, 32, data, (int)sizeof(data)) != sizeof(data))
		throw "Encryption failed(3)";

	if (y.Decrypt(data, (int)sizeof(data)) != 32)
		throw "Decryption failed for IV 1";
}

/*
 * Verify that packets can be received out of order up to a certain distance
 */
void ReplayWindowTest()
{
	char key[32] = {0};

	Calico x, y;

	if (x.Initialize(key, "Replay Window Test", INITIATOR) != ERR_GROOVY)
		throw "Unable to initialize x";

	if (y.Initialize(key, "Replay Window Test", RESPONDER) != ERR_GROOVY)
		throw "Unable to initialize y";

	char data[32 + Calico::OVERHEAD] = {0};

	// Advance IV for x by 2048 (simulate dropping lots of packets)
	for (int ii = 0; ii < 2048; ++ii)
	{
		if (x.Encrypt(data, 32, data, (int)sizeof(data)) != sizeof(data))
			throw "Encryption failed";
	}

	// Deliver the last one
	if (y.Decrypt(data, (int)sizeof(data)) != 32)
		throw "Decryption failed";

	// Now replay them all

	if (x.Initialize(key, "Replay Window Test", INITIATOR) != ERR_GROOVY)
		throw "Unable to initialize x(2)";

	for (int ii = 0; ii < 1024; ++ii)
	{
		if (x.Encrypt(data, 32, data, (int)sizeof(data)) != sizeof(data))
			throw "Encryption failed";

		if (y.Decrypt(data, (int)sizeof(data)) != ERR_IV_DROP)
			throw "Did not drop old packet";
	}

	for (int ii = 1024; ii < 2047; ++ii)
	{
		if (x.Encrypt(data, 32, data, (int)sizeof(data)) != sizeof(data))
			throw "Encryption failed";

		if (y.Decrypt(data, (int)sizeof(data)) != 32)
			throw "Did not accept out of order packet";
	}

	// Test replay of original packet

	if (x.Encrypt(data, 32, data, (int)sizeof(data)) != sizeof(data))
		throw "Encryption failed";

	if (y.Decrypt(data, (int)sizeof(data)) != ERR_IV_DROP)
		throw "Did not drop original packet";

	// Test some forward movement

	for (int ii = 0; ii < 1024; ++ii)
	{
		if (x.Encrypt(data, 32, data, (int)sizeof(data)) != sizeof(data))
			throw "Encryption failed";

		if (y.Decrypt(data, (int)sizeof(data)) != 32)
			throw "Did not accept new packet";
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
		Calico x;

		if (x.Initialize(key, "Initialize Test", INITIATOR) != ERR_GROOVY)
			throw "Unable to initialize INITIATOR";
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
	char key[32 + 8] = {0};
	Calico x;

	if (x.Initialize(key, "Encryption Test", INITIATOR) != ERR_GROOVY)
		throw "Unable to initialize INITIATOR";

	char orig[10000 + Calico::OVERHEAD] = {0};
	char data[10000 + Calico::OVERHEAD] = {0};

	for (int bytes = 10000; bytes > 0; bytes /= 10)
	{
		double t0 = m_clock.usec();

		for (int ii = 0; ii < 100000; ++ii)
		{
			if (x.Encrypt(orig, bytes, data, (int)sizeof(data)) != bytes + Calico::OVERHEAD)
				throw "Encryption failed";
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
	char key[32 + 8] = {0};
	Calico x, y;

	if (x.Initialize(key, "Decryption Fail Test", INITIATOR) != ERR_GROOVY)
		throw "Unable to initialize x";

	if (y.Initialize(key, "Decryption Fail Test", RESPONDER) != ERR_GROOVY)
		throw "Unable to initialize y";

	char data[10000 + Calico::OVERHEAD] = {0};

	for (int bytes = 10000; bytes > 0; bytes /= 10)
	{
		if (x.Encrypt(data, bytes, data, (int)sizeof(data)) != bytes + Calico::OVERHEAD)
			throw "Encryption failed";

		data[0] ^= 1;

		double t0 = m_clock.usec();

		for (int ii = 0; ii < 100000; ++ii)
		{
			if (y.Decrypt(data, bytes + Calico::OVERHEAD) != ERR_MAC_DROP)
				throw "Did not drop due to MAC failure";
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
	Calico x, y;

	if (x.Initialize(key, "Decryption Success Test", INITIATOR) != ERR_GROOVY)
		throw "Unable to initialize x";

	if (y.Initialize(key, "Decryption Success Test", RESPONDER) != ERR_GROOVY)
		throw "Unable to initialize y";

	char data[10000 + Calico::OVERHEAD];
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
			if (x.Encrypt(temp, bytes, data, (int)sizeof(data)) != bytes + Calico::OVERHEAD)
				throw "Encryption failed";

			double t0 = m_clock.usec();

			int r = y.Decrypt(data, bytes + Calico::OVERHEAD);
			if (r != bytes)
			{
				cerr << "Return code: " << Calico::GetErrorString(r) << endl;
				throw "Decrypt failure";
			}

			double t1 = m_clock.usec();

			if (memcmp(data, temp, bytes))
				throw "Data got corrupted";

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
	char data[10000 + Calico::OVERHEAD];
	char orig[10000 + Calico::OVERHEAD];

	Abyssinian prng;
	prng.Initialize(m_clock.msec(), Clock::cycles());

	for (int ii = 0; ii < 1000; ++ii)
	{
		u32 key[8];

		for (int jj = 0; jj < 8; ++jj)
			key[jj] = prng.Next();

		Calico x, y;

		if (x.Initialize(key, "Stress Test", INITIATOR) != ERR_GROOVY)
			throw "Unable to initialize x";

		if (y.Initialize(key, "Stress Test", RESPONDER) != ERR_GROOVY)
			throw "Unable to initialize y";

		u32 *data_ptr = reinterpret_cast<u32*>( orig );

		for (int messages = 0; messages < 1000; ++messages)
		{
			// Send x -> y

			int len = prng.Next() % 10000;

			for (int jj = 0; jj < (len + 3) / 4; ++jj)
				data_ptr[jj] = prng.Next();

			if (x.Encrypt(orig, len, data, sizeof(data)) != len + Calico::OVERHEAD)
				throw "Encryption failed";

			// Add 5% packetloss
			if (prng.Next() % 100 >= 5)
			{
				if (y.Decrypt(data, len + Calico::OVERHEAD) != len)
					throw "Decryption failed";

				if (memcmp(data, orig, len))
					throw "Data corrupted in flight";
			}

			// Send y -> x

			len = prng.Next() % 10000;

			for (int jj = 0; jj < (len + 3) / 4; ++jj)
				data_ptr[jj] = prng.Next();

			if (y.Encrypt(orig, len, data, sizeof(data)) != len + Calico::OVERHEAD)
				throw "Encryption failed";

			// Add 5% packetloss
			if (prng.Next() % 100 >= 5)
			{
				if (x.Decrypt(data, len + Calico::OVERHEAD) != len)
					throw "Decryption failed";

				if (memcmp(data, orig, len))
					throw "Data corrupted in flight";
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

