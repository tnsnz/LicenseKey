#include <openssl/applink.c>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <iostream>
#include <fstream>

void initializeOpenSSL() {
	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS | OPENSSL_INIT_LOAD_CONFIG, nullptr);
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
}

RSA* loadPublicKey(const std::string& publicKeyFile) {
	FILE* publicKeyFilePtr = fopen(publicKeyFile.c_str(), "rb");
	if (!publicKeyFilePtr) {
		std::cerr << "Error opening public key file." << std::endl;
		return nullptr;
	}
	RSA* rsa = PEM_read_RSAPublicKey(publicKeyFilePtr, nullptr, nullptr, nullptr);
	fclose(publicKeyFilePtr);
	return rsa;
}

bool verifySignature(const std::string& message, const std::string& signature, const std::string& publicKeyFile) {
	RSA* rsa = loadPublicKey(publicKeyFile);
	if (!rsa) return false;

	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256(reinterpret_cast<const unsigned char*>(message.c_str()), message.size(), hash);

	int result = RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH,
		reinterpret_cast<const unsigned char*>(signature.c_str()), signature.size(), rsa);
	RSA_free(rsa);

	return result == 1;
}

int main() {
	initializeOpenSSL();
	std::string publicKeyFile = "public key path";
	std::string licenseKey = "";

	std::ifstream in("license sig path", std::ios::binary);
	std::string signature((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
	in.close();

	if (verifySignature(licenseKey, signature, publicKeyFile))
	{
		std::cout << "Signature is valid. License key is authentic." << std::endl;
	}
	else
	{
		std::cout << "Invalid signature. License key is not authentic." << std::endl;
	}

	return 0;
}
