#include <util/types.h>
#include <stdio.h>
#include "esp.h"
#include "crypto.h"

// Key Length : 24 Bytes
typedef struct _3DES_Payload {
	uint64_t iv;
	uint8_t ep[0]; //encrypted payload
} __attribute__ ((packed)) _3DES_Payload;

static void _3des_cbc_encrypt(ESP* esp, size_t size, SA_ESP* sa) {
	_3DES_Payload* payload = (_3DES_Payload*)esp->payload;

	uint64_t iv;
	RAND_bytes((unsigned char*)(&iv), 8);
	payload->iv = iv;

	DES_key_schedule* ks_3 = ((SA_ESP*)sa)->encrypt_key;
	DES_ede3_cbc_encrypt((const unsigned char*)payload->ep,
							(unsigned char*)payload->ep, 
							size - 8 , &ks_3[0], &ks_3[1], &ks_3[2], (unsigned char(*)[8])&iv, DES_ENCRYPT);
}

static void _3des_cbc_decrypt(ESP* esp, size_t size, SA_ESP* sa) {
	_3DES_Payload* payload = (_3DES_Payload*)esp->payload;

	DES_key_schedule* ks_3 = ((SA_ESP*)sa)->encrypt_key;
	DES_ede3_cbc_encrypt((const unsigned char*)payload->ep, 
							(unsigned char*)payload->ep, 
							size - 8 , &ks_3[0], &ks_3[1], &ks_3[2], (unsigned char(*)[8])&(payload->iv), DES_DECRYPT);
}

// Key Length : 8 Bytes
typedef struct _DES_Payload {
	uint64_t iv;
	uint8_t ep[0]; //encrypted payload
} __attribute__ ((packed)) DES_Payload;

static void _des_cbc_encrypt(ESP* esp, size_t size, SA_ESP* sa) {
	DES_Payload* payload = (DES_Payload*)esp->payload;

	uint64_t iv;
	RAND_bytes((unsigned char*)(&iv), 8);
	payload->iv = iv;

	DES_ncbc_encrypt((const unsigned char *)payload->ep, 
			(unsigned char *)payload->ep,
			size - 8, ((SA_ESP*)sa)->encrypt_key, (unsigned char(*)[8])&iv, DES_ENCRYPT);
}

static void _des_cbc_decrypt(ESP* esp, size_t size, SA_ESP* sa) {
	DES_Payload* payload = (DES_Payload*)esp->payload;

	DES_ncbc_encrypt((const unsigned char *)payload->ep, 
			(unsigned char *)payload->ep,
			size - 8, ((SA_ESP*)sa)->decrypt_key, (unsigned char(*)[8])&(payload->iv), DES_DECRYPT);
}

// Key Length : 5 ~ 56 Bytes (Default : 16 Bytes)
typedef struct _Blowfish_Payload {
	uint64_t iv;
	uint8_t ep[0]; //encrypted payload
} __attribute__ ((packed)) Blowfish_Payload;

static void _blowfish_cbc_encrypt(ESP* esp, size_t size, SA_ESP* sa) {
	Blowfish_Payload* payload = (Blowfish_Payload*)esp->payload;

	uint64_t iv;
	RAND_bytes((unsigned char*)(&iv), 8);
	payload->iv = iv;
	
	BF_cbc_encrypt((const unsigned char *)payload->ep, 
			(unsigned char *)payload->ep, 
			size - 8, ((SA_ESP*)sa)->encrypt_key, (unsigned char*)(&iv), BF_ENCRYPT);
}

static void _blowfish_cbc_decrypt(ESP* esp, size_t size, SA_ESP* sa) {
	Blowfish_Payload* payload = (Blowfish_Payload*)esp->payload;

	BF_cbc_encrypt((const unsigned char *)payload->ep, 
			(unsigned char *)payload->ep, 
			size - 8, ((SA_ESP*)sa)->decrypt_key, (unsigned char*)(&(payload->iv)), BF_DECRYPT);
}

// Key Length : 5 ~ 56 Bytes (Default : 16 Bytes)
typedef struct _Cast128_Payload {
	uint64_t iv;
	uint8_t ep[0]; //encrypted payload
} __attribute__ ((packed)) Cast128_Payload;

static void _cast128_cbc_encrypt(ESP* esp, size_t size, SA_ESP* sa) {
	Cast128_Payload* payload = (Cast128_Payload*)esp->payload;

	uint64_t iv;
	RAND_bytes((unsigned char*)(&iv), 8);
	payload->iv = iv;

	CAST_cbc_encrypt((const unsigned char *)payload->ep,
			(unsigned char *)payload->ep,
			size - 8, ((SA_ESP*)sa)->encrypt_key, (unsigned char *)&iv, CAST_ENCRYPT);
}

static void _cast128_cbc_decrypt(ESP* esp, size_t size, SA_ESP* sa) {
	Cast128_Payload* payload = (Cast128_Payload*)esp->payload;

	CAST_cbc_encrypt((const unsigned char *)payload->ep, 
			(unsigned char *)payload->ep, 
			size - 8, ((SA_ESP*)sa)->decrypt_key, (unsigned char *)(&(payload->iv)), CAST_DECRYPT);
}

static void _des_deriv_encrypt(ESP* esp, size_t size, SA_ESP* sa){
}

static void _des_deriv_decrypt(ESP* esp, size_t size, SA_ESP* sa){
}

static void _3des_deriv_encrypt(ESP* esp, size_t size, SA_ESP* sa){
}

static void _3des_deriv_decrypt(ESP* esp, size_t size, SA_ESP* sa){
}

// TODO : 16 Byte Alighment for Payload
// Key Length : 16, 24, 32 Bytes (Default : 16 Bytes)
typedef struct _Rijndael_CBC_Payload {
	uint64_t iv[2];
	uint8_t ep[0]; //encrypted payload
} __attribute__ ((packed)) Rijndael_CBC_Payload;

static void _rijndael_cbc_encrypt(ESP* esp, size_t size, SA_ESP* sa) {
	Rijndael_CBC_Payload* payload = (Rijndael_CBC_Payload*)esp->payload;

	uint64_t iv[2];
	RAND_bytes((unsigned char*)(&iv), 16);
	memcpy(payload->iv, iv, 16);
	
	AES_cbc_encrypt((const unsigned char *)payload->ep,
			(unsigned char *)payload->ep,
			size - 16, ((SA_ESP*)sa)->encrypt_key, (unsigned char *)(&iv), AES_ENCRYPT);
}

static void _rijndael_cbc_decrypt(ESP* esp, size_t size, SA_ESP* sa) {
	Rijndael_CBC_Payload* payload = (Rijndael_CBC_Payload*)esp->payload;

	AES_cbc_encrypt((const unsigned char *)payload->ep, 
			(unsigned char *)payload->ep, 
			size - 16, ((SA_ESP*)sa)->decrypt_key, (unsigned char*)(&(payload->iv)), AES_DECRYPT);
}

/*
   Not implemented : No openssl function 

   AES and Triple DES are considered to be strong. Blowfish is still a good algorithm but its author (Bruce Schneier) recommends that you should use the "twofish" algorithm instead if available. Unfortunately twofish is not yet available in the list of openssl ciphers.
*/
typedef struct _TwoFish_Payload {
	uint64_t iv[2];
	uint8_t ep[0]; //encrypted payload
} __attribute__ ((packed)) TwoFish_Payload;

static void _twofish_cbc_encrypt(ESP* esp, size_t size, SA_ESP* sa) {
}

static void _twofish_cbc_decrypt(ESP* esp, size_t size, SA_ESP* sa) {
}

// Key Length : 16, 24, 32 Bytes (Default : 16 Bytes) Nonce : 4 Bytes
typedef struct _AES_Ctr_Payload {
	uint64_t iv;
	uint8_t ep[0]; //encrypted payload
} __attribute__ ((packed)) AES_Ctr_Payload;

static int init_ctr_block(uint32_t block[4], uint32_t nonce, uint64_t iv, uint32_t num) {
	memset(block, 0, sizeof(uint32_t) * 4);

	block[0] = nonce;
	memcpy(&block[1], &iv, 8);
	block[3] = endian32(num);

	return 0;
}

static uint32_t get_nonce(SA_ESP* sa) {
	uint32_t* nonce;
	uint8_t* key = (uint8_t*)sa->crypto_key;
	nonce = (uint32_t*)(key + sa->crypto_key_length - 4);

	return *nonce;
}

static void _aes_ctr_encrypt(ESP* esp, size_t size, SA_ESP* sa) {
	AES_Ctr_Payload* payload = (AES_Ctr_Payload*)esp->payload;

	uint64_t iv;
	RAND_bytes((unsigned char*)(&iv), 8);
	memcpy(&(payload->iv), &iv, 8);

	uint8_t ctr_block[16];
	uint32_t nonce = get_nonce(sa);
	for(int i = 1; (i - 1) * 16 < size - 8; i++) {
		init_ctr_block((uint32_t*)ctr_block, nonce, payload->iv, i);

		AES_encrypt((const unsigned char*)ctr_block, (unsigned char*)ctr_block, ((SA_ESP*)sa)->decrypt_key);

		for(int j = 0 ;j < 16 && ((i - 1) * 16 + j) < size - 8; j++) {
			*(((uint8_t*)payload->ep + ((i - 1) * 16) + j)) ^= ctr_block[j];
		}
	}
}

static void _aes_ctr_decrypt(ESP* esp, size_t size, SA_ESP* sa) {
	AES_Ctr_Payload* payload = (AES_Ctr_Payload*)esp->payload;

	uint8_t ctr_block[16];
	uint32_t nonce = get_nonce(sa);
	for(int i = 1; (i - 1) * 16 < size - 8; i++) {
		init_ctr_block((uint32_t*)ctr_block, nonce, payload->iv, i);

		AES_encrypt((const unsigned char*)ctr_block, (unsigned char*)ctr_block, ((SA_ESP*)sa)->decrypt_key);

		for(int j = 0 ;j < 16 && ((i - 1) * 16 + j) < size - 8; j++) {
			*(((uint8_t*)payload->ep + ((i - 1) * 16) + j)) ^= ctr_block[j];
		}
	}
}

// TODO : 16 Byte Alighment for Payload
// Key Length : 16, 24, 32 Bytes (Default : 16 Bytes)
typedef struct _Camellia_CBC_Payload {
	uint64_t iv[2];
	uint8_t ep[0]; //encrypted payload
} __attribute__ ((packed)) Camellia_CBC_Payload;

static void _camellia_cbc_encrypt(ESP* esp, size_t size, SA_ESP* sa) {
	Camellia_CBC_Payload* payload = (Camellia_CBC_Payload*)esp->payload;

	uint64_t iv[2];
	RAND_bytes((unsigned char*)(&iv), 16);
	memcpy(payload->iv, iv, 16);
	
	Camellia_cbc_encrypt((const unsigned char *)payload->ep,
			(unsigned char *)payload->ep,
			size - 16, ((SA_ESP*)sa)->encrypt_key, (unsigned char *)iv, CAMELLIA_ENCRYPT);
}

static void _camellia_cbc_decrypt(ESP* esp, size_t size, SA_ESP* sa) {
	Camellia_CBC_Payload* payload = (Camellia_CBC_Payload*)esp->payload;

	Camellia_cbc_encrypt((const unsigned char *)payload->ep, 
			(unsigned char *)payload->ep, 
			size - 16, ((SA_ESP*)sa)->decrypt_key, (unsigned char *)payload->iv, CAMELLIA_DECRYPT);
}

Cryptography cryptographys[] = {
	{
		.encrypt = _des_cbc_encrypt,
		.decrypt = _des_cbc_decrypt,
		.iv_len = 8
	},
	{
		.encrypt = _3des_cbc_encrypt,
		.decrypt = _3des_cbc_decrypt,
		.iv_len = 8
	},
	{
		.encrypt = _blowfish_cbc_encrypt,
		.decrypt = _blowfish_cbc_decrypt,
		.iv_len = 8
	},
	{
		.encrypt = _cast128_cbc_encrypt,
		.decrypt = _cast128_cbc_decrypt,
		.iv_len = 8
	},
	{
		.encrypt = _des_deriv_encrypt,
		.decrypt = _des_deriv_decrypt,
		.iv_len = 8
	},
	{
		.encrypt = _3des_deriv_encrypt,
		.decrypt = _3des_deriv_decrypt,
		.iv_len = 8
	},
	{
		.encrypt = _rijndael_cbc_encrypt,
		.decrypt = _rijndael_cbc_decrypt,
		.iv_len = 16
	},
	{
		.encrypt = _twofish_cbc_encrypt,
		.decrypt = _twofish_cbc_decrypt,
		.iv_len = 16
	},
	{
		.encrypt = _aes_ctr_encrypt,
		.decrypt = _aes_ctr_decrypt,
		.iv_len = 8
	},
	{
		.encrypt = _camellia_cbc_encrypt,
		.decrypt = _camellia_cbc_decrypt,
		.iv_len = 16
	},
};

Cryptography* get_cryptography(int algorithm) {
	return &cryptographys[algorithm - 1];
}

