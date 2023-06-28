#include <Windows.h>
#include <stdio.h>
#include <fstream>
#include <vector>
#include "rc4.hpp"


void encrypt(unsigned char* data, size_t length, const char* key) {
	size_t keyLength = strlen(key);
	for (size_t i = 0; i < length; i++) {
		data[i] ^= key[i % keyLength];
	}
}

void decrypt(unsigned char* data, size_t length, const char* key) {
	encrypt(data, length, key);  // XOR encryption is reversible, so we can reuse the same function
}

int main(int argc, char* argv[])
{
	const char* payloadPath = argv[1];
	const char* encryptionKey = argv[2];

	struct rc4_state* s;
	s = (struct rc4_state*)malloc(sizeof(struct rc4_state));

	std::ifstream payload(payloadPath, std::ios::binary);
	std::vector<unsigned char> payloadBuffer(std::istreambuf_iterator<char>(payload), {});
	payload.close();

	encrypt(payloadBuffer.data(), payloadBuffer.size(), encryptionKey);

	std::ofstream outputFile("encrypted.bin", std::ios::binary);
	if (!outputFile.is_open()) {
		printf("[-] Failed!\n");
		return FALSE;
	}
	outputFile.write((const char*)payloadBuffer.data(), payloadBuffer.size());
}