//thanks to caali for help
#include "Rabbit.h"
#include <stdint.h>

Cryptography::Cryptor::Rabbit decryptor;
Cryptography::Cryptor::Rabbit encryptor;
Cryptography::Cryptor::Rabbit decryptor2;
Cryptography::Cryptor::Rabbit encryptor2;

uint8_t clientkey1[128];
uint8_t clientkey2[128];
uint8_t serverkey1[128];
uint8_t serverkey2[128];
uint8_t decryptkey[128];
uint8_t encryptkey[128];
uint8_t decryptkey2[128];
uint8_t encryptkey2[128];


void setKeyAndIV(Cryptography::Cryptor::Rabbit& ctx, uint8_t* sessionkey) {
	static constexpr size_t keyoffset = 56;
	ctx.setKey(&sessionkey[keyoffset], 16);
	size_t idx = keyoffset + 16;
	for (; idx < 128; idx += 8) {
		ctx.setIV(&sessionkey[idx], 8);
	}
	for (size_t i = idx % 128; i < keyoffset; i += 8) {
		ctx.setIV(&sessionkey[i], 8);
	}
}

void shiftkey(uint8_t* destination, uint8_t* source, uint32_t n, bool direction)
{
	for (uint32_t i = 0; i < 128; i++) {
		if (direction) {
			destination[(i + n) % 128] = source[i];
		}
		else {
			destination[i] = source[(i + n) % 128];
		}
	}
}
void xorkey(uint8_t* destination, uint8_t* key1, uint8_t* key2)
{
	for (uint32_t i = 0; i < 128; i++)
		destination[i] = (key1[i] ^ key2[i]);
}

void initCrypto()
{
    uint8_t tmp_key1[128], tmp_key2[128];

	shiftkey(&tmp_key1[0], serverkey1, 100);

	xorkey(&tmp_key2[0], &tmp_key1[0], clientkey1);

	shiftkey(&tmp_key1[0], clientkey2, 36, false);

	xorkey(decryptkey, &tmp_key1[0], &tmp_key2[0]);

	memcpy(decryptkey2, decryptkey, 128);

	setKeyAndIV(decryptor, decryptkey);
	setKeyAndIV(decryptor2, decryptkey2);

	shiftkey(encryptkey, serverkey2, 79);

	memcpy(encryptkey2, encryptkey, 128);

	decryptor.apply(encryptkey, 128);
	decryptor2.apply(encryptkey2, 128);
	setKeyAndIV(encryptor, encryptkey);
	setKeyAndIV(encryptor2, encryptkey2);
}