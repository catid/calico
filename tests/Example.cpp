#include <iostream>
using namespace std;

#include "Calico.hpp" // <-- Add this include file
using namespace cat::calico;

int main()
{
	// Declare the sender and receiver ends of the tunnel
	Calico sender, receiver;

	// Choose a secret key
	char key[32] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	// Never use the same secret key twice.  Always use a new, random key every
	// time a new tunnel is created.  How to share a new key is outside of the
	// scope of this library.

	// Choose a unique session name for each tunnel
	const char *session_name = "Example Session";

	// If you have multiple sessions from the same key, each one should have a
	// different session name.  This allows you to use one key to secure
	// several different sessions.

	int r;

	// Initialize the sender
	r = sender.Initialize(key, session_name, INITIATOR); // <-- Note INITIATOR mode

	// Aside from PACKET there is another mode called STREAM.
	// STREAM is used for TCP streams or other ordered reliable message queues.
	// PACKET is used for UDP endpoints for unreliable or unordered messaging.
	// There are a few differences.  STREAM has 8 bytes of overhead per
	// encrypted binary blob.  PACKET has 11 bytes of overhead per blob.
	// PACKET adds an IV to each encrypted blob so that it can synchronize with
	// the transmitter despite datagrams arriving out of order or getting lost.

	// Handle an error result
	if (r < 0)
	{
		cerr << "Unable to initialize: " << Calico::GetErrorString(r) << endl;
		return 1;
	}

	// Initialize the receiver
	r = receiver.Initialize(key, session_name, RESPONDER); // <-- Note RESPONDER mode

	// It is really important that the sender and receiver use different modes.
	// The client/initiator/requestor should use the INITIATOR mode and
	// the server/responder/answerer should use the RESPONDER mode.

	// Handle an error result
	if (r < 0)
	{
		cerr << "Unable to initialize: " << Calico::GetErrorString(r) << endl;
		return 2;
	}

	// Choose a message to send
	const char *message = "The message was sent through the Calico secure tunnel successfully!";
	int message_length = strlen(message) + 1;

	// Declare a packet buffer to store the message
	char packet[1500];

	// Encrypt the message into the packet, adding some overhead (11 bytes)
	r = sender.Encrypt(message, message_length, packet, sizeof(packet));

	// Handle an error result
	if (r < 0)
	{
		cerr << "Unable to encrypt: " << Calico::GetErrorString(r) << endl;
		return 3;
	}

	// The return value is the size of the encrypted data if it succeeded
	int encrypted_size = r;


	// <-- Pretend that right here we sent the "packet" over the Internet.


	// Decrypt the message in-place, recovering the original message
	r = receiver.Decrypt(packet, encrypted_size);

	// Handle an error result
	if (r < 0)
	{
		cerr << "Unable to decrypt: " << Calico::GetErrorString(r) << endl;
		return 4;
	}

	// The return value is the size of the decrypted data if it succeeded
	int decrypted_size = r;

	// The decrypted message size should match the original message size
	if (decrypted_size != message_length)
	{
		cerr << "Message size did not match." << endl;
		return 5;
	}

	// And the decrypted message contents will match the original message
	if (memcmp(message, packet, decrypted_size))
	{
		cerr << "Message contents have been mangled." << endl;
		return 6;
	}

	cout << packet << endl;
	return 0;
}
