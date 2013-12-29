#include <iostream>
#include <cassert>
using namespace std;

#include "calico.h" // <-- Add this include file

int main()
{
	// Allocate state objects
	calico_state initiator, responder;

	// Always initialize Calico before using it
	assert(!calico_init());

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

	assert(!calico_key(&initiator, CALICO_INITIATOR, key, sizeof(key)));

	assert(!calico_key(&responder, CALICO_RESPONDER, key, sizeof(key)));

	// Choose a message to send
	const char *message = "The message was sent through the Calico secure tunnel successfully!";
	int message_length = strlen(message) + 1;

	// Declare a packet buffer to store the message
	char packet[1500];
	int packet_len;


	// UDP example:

	// Encrypt the message into the packet, adding some overhead (11 bytes)
	packet_len = sizeof(packet);
	assert(!calico_datagram_encrypt(&initiator, message, message_length, packet, &packet_len));


	// <-- Pretend that right here we sent the UDP packet over the Internet.


	// Decrypt the message from the packet
	assert(!calico_datagram_decrypt(&responder, packet, &packet_len));

	// The decrypted message size should match the original message size
	assert(packet_len == message_length);

	// And the decrypted message contents will match the original message
	assert(!memcmp(message, packet, packet_len));

	cout << packet << endl;


	// TCP example:

	// Encrypt the message into the packet, adding some overhead (8 bytes)
	packet_len = sizeof(packet);
	assert(!calico_stream_encrypt(&initiator, message, message_length, packet, &packet_len));


	// <-- Pretend that right here we sent the TCP message over the Internet.


	// Decrypt the message from the packet
	assert(!calico_stream_decrypt(&responder, packet, &packet_len));

	// The decrypted message size should match the original message size
	assert(packet_len == message_length);

	// And the decrypted message contents will match the original message
	assert(!memcmp(message, packet, packet_len));

	cout << packet << endl;

	return 0;
}

