//#include <dll.h>
#include <iostream>
#include <fstream>
#include <cassert>
#include <string_view>
#include <cryptlib.h>
#include <des.h>
#include <modes.h>
#include <filters.h>
#include <osrng.h>
#include <rsa.h>
#include <files.h>
#include <base64.h>
#include <pem.h>
#include <hex.h>

using namespace std;
using namespace CryptoPP;

void Load(const string& filename, BufferedTransformation& bt)
{
	FileSource file(filename.c_str(), true /*pumpAll*/);

	file.TransferTo(bt);
	bt.MessageEnd();
}

void LoadPublicKey(const string& filename, PublicKey& key)
{
	ByteQueue queue;
	Load(filename, queue);

	key.Load(queue);
}

void Save(const string& filename, const BufferedTransformation& bt)
{
	FileSink file(filename.c_str());

	bt.CopyTo(file);
	file.MessageEnd();
}

void SavePublicKey(const string& filename, const PublicKey& key)
{
	ByteQueue queue;
	key.Save(queue);

	Save(filename, queue);
}

void Sample() {
	AutoSeededRandomPool prng;

	SecByteBlock key(0x00, DES_EDE2::DEFAULT_KEYLENGTH);
	prng.GenerateBlock(key, key.size());

	CryptoPP::byte iv[DES_EDE2::BLOCKSIZE];
	prng.GenerateBlock(iv, sizeof(iv));

	string plain = "CBC Mode Test";
	string cipher, encoded, recovered;

	/*********************************\
	\*********************************/

	try
	{
		cout << "plain text: " << plain << endl;

		CBC_Mode< DES_EDE2 >::Encryption e;
		e.SetKeyWithIV(key, key.size(), iv);

		// The StreamTransformationFilter adds padding
		//  as required. ECB and CBC Mode must be padded
		//  to the block size of the cipher.
		StringSource ss1(plain, true,
			new StreamTransformationFilter(e,
				new StringSink(cipher)
			) // StreamTransformationFilter      
		); // StringSource
	}
	catch (const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	// Pretty print
	StringSource ss2(cipher, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource

	cout << "cipher text: " << encoded << endl;

	/*********************************\
	\*********************************/

	try
	{
		CBC_Mode< DES_EDE2 >::Decryption d;
		d.SetKeyWithIV(key, key.size(), iv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource ss3(cipher, true,
			new StreamTransformationFilter(d,
				new StringSink(recovered)
			) // StreamTransformationFilter
		); // StringSource

		cout << "recovered text: " << recovered << endl;
	}
	catch (const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}
}


void EncodeRSA(string& filename) {
	////////////////////////////////////////////////
	// Generate keys
	AutoSeededRandomPool rng;

	RSA::PrivateKey privateKey;
	privateKey.GenerateRandomWithKeySize(rng, 3072);

	RSA::PublicKey publicKey(privateKey);

	SavePublicKey("privateKey.txt", privateKey);

	////////////////////////////////////////////////
	// Secret to protect
	ifstream file_input(filename, ios::binary);
	if (!file_input)
	{
		cerr << "Can`t open file to read from" << endl;
		return;
	}
	size_t filesize = file_input.tellg();
	string plaintext(filesize, '\0');
	file_input.read(&plaintext[0], filesize);
	const unsigned char* byte_plaintext = (unsigned char*)(plaintext.c_str());

	////////////////////////////////////////////////
	// Encrypt
	RSAES_OAEP_SHA_Encryptor encryptor(publicKey);

	// Now that there is a concrete object, we can validate
	assert(0 != encryptor.FixedMaxPlaintextLength());
	assert(plaintext.size() <= encryptor.FixedMaxPlaintextLength());

	// Create cipher text space
	size_t ecl = encryptor.CiphertextLength(plaintext.size());
	assert(0 != ecl);
	SecByteBlock ciphertext(ecl);

	encryptor.Encrypt(rng, byte_plaintext, plaintext.size(), ciphertext);

	// Put encoded data into file
	string out_filename = filename.substr(0, filename.find('.')-1) + "_rsa.enc";
	ofstream file_output(out_filename, ios::binary);
	if (!file_output)
	{
		cerr << "Can`t open file to write" << endl;
		return;
	}
	string ciphertext_s(reinterpret_cast<const char*>(&ciphertext[0]), ciphertext.size());
	file_output << ciphertext_s;
	cout << "File succesefully coded !" << endl;
}

void DecodeRSA(string& filename) {
	////////////////////////////////////////////////
	// Load key

	RSA::PrivateKey privateKey;
	LoadPublicKey("privateKey.txt", privateKey);

	// Get encoded data from file
	ifstream file_input(filename, ios::binary);
	if (!file_input)
	{
		cerr << "Can`t open file to read" << endl;
		return;
	}
	string ciphertext{ std::istreambuf_iterator<char>(file_input), std::istreambuf_iterator<char>() };

	////////////////////////////////////////////////
	// Decrypt
	RSAES_OAEP_SHA_Decryptor decryptor(privateKey);

	// Now that there is a concrete object, we can check sizes
	assert(0 != decryptor.FixedCiphertextLength());
	assert(ciphertext.size() <= decryptor.FixedCiphertextLength());

	// Create recovered text space
	size_t dpl = decryptor.MaxPlaintextLength(ciphertext.size());
	assert(0 != dpl);
	SecByteBlock recovered(dpl);

	AutoSeededRandomPool rng;
	const unsigned char* byte_ciphertext = (unsigned char*)(ciphertext.c_str());
	DecodingResult result = decryptor.Decrypt(rng,
		byte_ciphertext, ciphertext.size(), recovered);

	// More sanity checks
	assert(result.isValidCoding);
	assert(result.messageLength <= decryptor.MaxPlaintextLength(ciphertext.size()));

	// At this point, we can set the size of the recovered
	//  data. Until decryption occurs (successfully), we
	//  only know its maximum size
	recovered.resize(result.messageLength);

	// SecByteBlock is overloaded for proper results below
	//assert(plaintext == recovered);

	cout << "Recovered plain text: " << recovered << endl;
}

void Encode3DES(string& filename) {
	AutoSeededRandomPool prng;

	SecByteBlock key(0x00, DES_EDE2::DEFAULT_KEYLENGTH);
	prng.GenerateBlock(key, key.size());

	CryptoPP::byte iv[DES_EDE2::BLOCKSIZE];
	prng.GenerateBlock(iv, sizeof(iv));

	string plain = "CBC Mode Test";
	string cipher, encoded, recovered;

	/*********************************\
	\*********************************/

	try
	{
		cout << "plain text: " << plain << endl;

		CBC_Mode< DES_EDE2 >::Encryption e;
		e.SetKeyWithIV(key, key.size(), iv);

		// The StreamTransformationFilter adds padding
		//  as required. ECB and CBC Mode must be padded
		//  to the block size of the cipher.
		StringSource ss1(plain, true,
			new StreamTransformationFilter(e,
				new StringSink(cipher)
			) // StreamTransformationFilter      
		); // StringSource
	}
	catch (const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	// Pretty print
	StringSource ss2(cipher, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource

	// Put encoded data into file
	string out_filename = filename.substr(0, filename.find('.') - 1) + "_3des.enc";
	ofstream file_output(out_filename, ios::binary);
	if (!file_output)
	{
		cerr << "Can`t open file to write" << endl;
		return;
	}
	file_output << encoded;

	ofstream key_file_output("3des_key.txt", ios::binary);
	if (!key_file_output)
	{
		cerr << "Can`t open file to write key" << endl;
		return;
	}
	string key_s((char*)key.BytePtr(), key.size());
	key_file_output << key_s;

	ofstream iv_file_output("3des_iv.txt", ios::binary);
	if (!iv_file_output)
	{
		cerr << "Can`t open file to write iv" << endl;
		return;
	}
	string iv_s((char*)iv, DES_EDE2::BLOCKSIZE);
	iv_file_output << iv_s;

	cout << "cipher text: " << encoded << endl;
	cout << "key length: " << key_s.length() << endl;
	cout << "iv: " << iv_s << endl;
	cout << "iv length: " << DES_EDE2::BLOCKSIZE << endl;
}

void Decode3DES(string& filename) {
	string recovered;
	ifstream file_input(filename, ios::binary);
	if (!file_input)
	{
		cerr << "Can`t open file to read data" << endl;
		return;
	}
	string cipher{ std::istreambuf_iterator<char>(file_input), std::istreambuf_iterator<char>() };

	ifstream key_file_input("3des_key.txt", ios::binary);
	if (!key_file_input)
	{
		cerr << "Can`t open file to read key" << endl;
		return;
	}
	string key_s{ std::istreambuf_iterator<char>(key_file_input), std::istreambuf_iterator<char>() };
	SecByteBlock key((const unsigned char*)key_s.c_str(), key_s.length());

	ifstream iv_file_input("3des_iv.txt", ios::binary);
	if (!iv_file_input)
	{
		cerr << "Can`t open file to read iv" << endl;
		return;
	}
	string iv_s{ std::istreambuf_iterator<char>(iv_file_input), std::istreambuf_iterator<char>() };
	CryptoPP::byte iv[DES_EDE2::BLOCKSIZE];
	memcpy(iv, iv_s.c_str(), iv_s.length());

	try
	{
		CBC_Mode< DES_EDE2 >::Decryption d;
		d.SetKeyWithIV(key, key.size(), iv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource ss3(cipher, true,
			new StreamTransformationFilter(d,
				new StringSink(recovered)
			) // StreamTransformationFilter
		); // StringSource

		cout << "recovered text: " << recovered << endl;
	}
	catch (const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}
}

int main(){

	//cout << "Choose coding : 1 - Cryptlib 3DES, 2 - Bouncy Castle RSA\nOr decoding : 3 - Cryptlib 3DES, 4 - Bouncy Castle" << endl;
	while (true) {
		int type = 0;
		cin >> type;
		if (type == 1) {
			string filename;
			cin >> filename;
			EncodeRSA(filename);
		}
		else if (type == 2) {
			string filename;
			cin >> filename;
			DecodeRSA(filename);
		}
		else if (type == 3) {
			string filename;
			cin >> filename;
			Encode3DES(filename);
		}
		else if (type == 4) {
			string filename;
			cin >> filename;
			Decode3DES(filename);
		}
		else if (type == 6) {
			Sample();
		}
		else if (type == 5) {
			return 0;
		}
		else
			cout << "You inserted incorrest number!";
	}

	return 0;
}