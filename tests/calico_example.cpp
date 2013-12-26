#include <iostream>
using namespace std;

#include "calico.h" // <-- Add this include file

int main()
{
	// Allocate state objects
	calico_state initiator, responder;

	// Choose a secret key
	// This should be generated from a key agreement protocol like Tabby
	char key[32] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	// Never use the same secret key twice.  Always use a new, random key every
	// time you call calico_key.

	if (calico_key(&initiator, CALICO_INITIATOR, key)) {
		throw "Failure";
	}

	if (calico_key(&responder, CALICO_RESPONDER, key)) {
		throw "Failure";
	}

	// Choose a message to send
	const char *message = "The message was sent through the Calico secure tunnel successfully!";
	int message_length = strlen(message) + 1;

	// Declare a packet buffer to store the message
	char packet[1500];
	int packet_len = 1500;

	// Encrypt the message into the packet, adding some overhead (11 bytes)
	if (calico_encrypt(&initiator, message, message_length, packet, &packet_len)) {
		throw "Failure";
	}


	// <-- Pretend that right here we sent the "packet" over the Internet.


	// Decrypt the message from the packet
	if (calico_decrypt(&responder, packet, &packet_len)) {
		throw "Failure";
	}

	// The decrypted message size should match the original message size
	if (packet_len != message_length)
	{
		throw "Failure";
	}

	// And the decrypted message contents will match the original message
	if (memcmp(message, packet, packet_len))
	{
		throw "Failure";
	}

	cout << packet << endl;
	return 0;
}

