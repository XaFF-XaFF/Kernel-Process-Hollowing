#include <Windows.h>
#include <stdio.h>
#include <fstream>
#include <vector>


void encrypt(unsigned char* data, size_t length, const char* key) {
	size_t keyLength = strlen(key);
	for (size_t i = 0; i < length; i++) {
		data[i] ^= key[i % keyLength];
	}
}

void decrypt(unsigned char* data, size_t length, const char* key) {
	encrypt(data, length, key);
}

int main(int argc, char* argv[])
{
	if (argc != 3)
	{
		printf("[+] Usage: EncryptPayload.exe PATH KEY\n");
		printf("[+] Example: EncryptPayload.exe C:\\Users\\Admin\\payload.exe 0123456789\n");
		return -1;
	}

	const char* payloadPath = argv[1];
	const char* encryptionKey = argv[2];

	std::ifstream payload(payloadPath, std::ios::binary);
	std::vector<unsigned char> payloadBuffer(std::istreambuf_iterator<char>(payload), {});
	payload.close();

	encrypt(payloadBuffer.data(), payloadBuffer.size(), encryptionKey);

	std::ofstream outputFile("payload.bin", std::ios::binary);
	if (!outputFile.is_open()) {
		printf("[-] Failed!\n");
		return FALSE;
	}
	outputFile.write((const char*)payloadBuffer.data(), payloadBuffer.size());
}