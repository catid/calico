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

	assert(!calico_key(&initiator, sizeof(initiator), CALICO_INITIATOR, key, sizeof(key)));

	assert(!calico_key(&responder, sizeof(initiator), CALICO_RESPONDER, key, sizeof(key)));

	// Choose a message to send
	const char *message = "The message was sent through the Calico secure tunnel successfully!";
	int message_length = strlen(message) + 1;

	// Declare a packet buffer to store the message
	char packet[1500];

	// Store overhead right after the message data
	char *overhead = packet + message_length;

	assert(message_length + CALICO_DATAGRAM_OVERHEAD < sizeof(packet));


	// UDP example:

	// Encrypt the message into the packet
	assert(!calico_encrypt(&initiator, packet, message, message_length, overhead, sizeof(overhead)));

	int packet_length = message_length + CALICO_DATAGRAM_OVERHEAD;


	// <-- Pretend that right here we sent the UDP packet over the Internet.

	int decoded_message_length = packet_length - CALICO_DATAGRAM_OVERHEAD;
	overhead = packet + decoded_message_length;

	assert(decoded_message_length >= 0);

	// Decrypt the message from the packet
	assert(!calico_decrypt(&responder, packet, decoded_message_length, overhead, sizeof(overhead)));

	// The decrypted message size should match the original message size
	assert(decoded_message_length == message_length);

	// And the decrypted message contents will match the original message
	assert(!memcmp(message, packet, message_length));

	cout << packet << endl;


	// TCP Stream example:

	*(int*)packet = message_length;
	overhead = packet + sizeof(int);
	char *packet_msg = packet + sizeof(int) + CALICO_STREAM_OVERHEAD;

	// Encrypt the message into the packet, adding some overhead (8 bytes)
	assert(!calico_encrypt(&initiator, packet_msg, message, message_length, overhead, sizeof(overhead)));


	// <-- Pretend that right here we sent the TCP message over the Internet.


	// Deframe the packet
	decoded_message_length = *(int*)packet;

	assert(decoded_message_length == message_length);

	overhead = packet + sizeof(int);

	packet_msg = packet + sizeof(int) + CALICO_STREAM_OVERHEAD;

	// Decrypt the message from the packet
	assert(!calico_decrypt(&responder, packet_msg, decoded_message_length, overhead, sizeof(overhead)));

	// And the decrypted message contents will match the original message
	assert(!memcmp(message, packet_msg, message_length));

	cout << packet_msg << endl;

	return 0;
}
