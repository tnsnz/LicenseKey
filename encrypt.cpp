#include <openssl/applink.c>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <map>
#include <direct.h>

using namespace std;

map<int, string> m;

void initializeOpenSSL() {
	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS | OPENSSL_INIT_LOAD_CONFIG, nullptr);
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
}

unsigned char* sha256(const std::string& str) {
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, str.c_str(), str.size());
	SHA256_Final(hash, &sha256);

	return hash;
}

void generateRSAKeys(const string& privateKeyFile, const string& publicKeyFile) {
	RSA* rsa = RSA_new();
	BIGNUM* bn = BN_new();
	BN_set_word(bn, RSA_F4);

	RSA_generate_key_ex(rsa, 2048, bn, nullptr);

	FILE* privateKeyFilePtr = fopen(privateKeyFile.c_str(), "wb");
	PEM_write_RSAPrivateKey(privateKeyFilePtr, rsa, nullptr, nullptr, 0, nullptr, nullptr);
	fclose(privateKeyFilePtr);

	FILE* publicKeyFilePtr = fopen(publicKeyFile.c_str(), "wb");
	PEM_write_RSAPublicKey(publicKeyFilePtr, rsa);
	fclose(publicKeyFilePtr);

	RSA_free(rsa);
	BN_free(bn);
}

string signMessage(const string& message, const string& privateKeyFile) {
	FILE* privateKeyFilePtr = fopen(privateKeyFile.c_str(), "rb");
	RSA* rsa = PEM_read_RSAPrivateKey(privateKeyFilePtr, nullptr, nullptr, nullptr);
	fclose(privateKeyFilePtr);

	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256(reinterpret_cast<const unsigned char*>(message.c_str()), message.size(), hash);

	unsigned char signature[SHA256_DIGEST_LENGTH * 8];
	unsigned int signatureLen;
	RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature, &signatureLen, rsa);

	RSA_free(rsa);

	return string(reinterpret_cast<char*>(signature), signatureLen);
}

int main() {
	initializeOpenSSL();

	m[1] = "mode 1";
	m[2] = "mode 2";
	m[4] = "mode 3";

	string defaultPath = "will be created path";

	string privateKeyFileName = "private_key.pem";
	string publicKeyFileName = "public_key.pem";
	string prefixSerial = "serial number prefix";
	string postfixSerial = "serial number postfix";

	for (int i = 1; i < 10000; i++) {
		string s = "";
		string serial = prefixSerial;
		ostringstream oss;
		oss << setw(4) << setfill('0') << i;
		s = oss.str();
		serial += s + postfixSerial;

		string serialDir = defaultPath + serial + "/";
		mkdir(serialDir.c_str());

		for (int j = 1; j <= 4 /* m.size's index square */; j *= 2)
		{
			string serialMode = serial + "_" + m[j];
			string serialModeDir = serialDir + serialMode + "/";
			mkdir(serialModeDir.c_str());

			string privateKeyFile = serialModeDir + privateKeyFileName;
			string publicKeyFile = serialModeDir + publicKeyFileName;
			generateRSAKeys(privateKeyFile, publicKeyFile);

			auto encryptedMsg = sha256(serialMode);

			std::stringstream ss;
			for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
				ss << std::hex << std::setw(2) << std::setfill('0') << (int)encryptedMsg[i];
			}

			string licenseKey = ss.str().substr(0, 16);

			ofstream out2(serialModeDir + "license_key.txt");
			out2.write(licenseKey.c_str(), licenseKey.size());
			out2.close();

			string signature = signMessage(licenseKey, privateKeyFile);
			ofstream out(serialModeDir + "license_key.sig", ios::binary);
			out.write(signature.c_str(), signature.size());
			out.close();

		}
	}

	return 0;
}
