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
							size , &ks_3[0], &ks_3[1], &ks_3[2], (unsigned char(*)[8])&iv, DES_ENCRYPT);
}

static void _3des_cbc_decrypt(ESP* esp, size_t size, SA_ESP* sa) {
	_3DES_Payload* payload = (_3DES_Payload*)esp->payload;

	DES_key_schedule* ks_3 = ((SA_ESP*)sa)->encrypt_key;
	DES_ede3_cbc_encrypt((const unsigned char*)payload->ep, 
							(unsigned char*)payload->ep, 
							size , &ks_3[0], &ks_3[1], &ks_3[2], (unsigned char(*)[8])&(payload->iv), DES_DECRYPT);
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
			size, ((SA_ESP*)sa)->encrypt_key, (unsigned char(*)[8])&iv, DES_ENCRYPT);
}

static void _des_cbc_decrypt(ESP* esp, size_t size, SA_ESP* sa) {
	DES_Payload* payload = (DES_Payload*)esp->payload;

	DES_ncbc_encrypt((const unsigned char *)payload->ep, 
			(unsigned char *)payload->ep,
			size, ((SA_ESP*)sa)->decrypt_key, (unsigned char(*)[8])&(payload->iv), DES_DECRYPT);
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
			size, ((SA_ESP*)sa)->encrypt_key, (unsigned char*)(&iv), BF_ENCRYPT);
}

static void _blowfish_cbc_decrypt(ESP* esp, size_t size, SA_ESP* sa) {
	Blowfish_Payload* payload = (Blowfish_Payload*)esp->payload;

	BF_cbc_encrypt((const unsigned char *)payload->ep, 
			(unsigned char *)payload->ep, 
			size, ((SA_ESP*)sa)->decrypt_key, (unsigned char*)(&(payload->iv)), BF_DECRYPT);
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
			size, ((SA_ESP*)sa)->encrypt_key, (unsigned char *)&iv, CAST_ENCRYPT);
}

static void _cast128_cbc_decrypt(ESP* esp, size_t size, SA_ESP* sa) {
	Cast128_Payload* payload = (Cast128_Payload*)esp->payload;

	CAST_cbc_encrypt((const unsigned char *)payload->ep, 
			(unsigned char *)payload->ep, 
			size, ((SA_ESP*)sa)->decrypt_key, (unsigned char *)(&(payload->iv)), CAST_DECRYPT);
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
			size, ((SA_ESP*)sa)->encrypt_key, (unsigned char *)(&iv), AES_ENCRYPT);
}

static void _rijndael_cbc_decrypt(ESP* esp, size_t size, SA_ESP* sa) {
	Rijndael_CBC_Payload* payload = (Rijndael_CBC_Payload*)esp->payload;

	AES_cbc_encrypt((const unsigned char *)payload->ep, 
			(unsigned char *)payload->ep, 
			size, ((SA_ESP*)sa)->decrypt_key, (unsigned char*)(&(payload->iv)), AES_DECRYPT);
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
	uint64_t iv[2];
	uint8_t ep[0]; //encrypted payload
} __attribute__ ((packed)) AES_Ctr_Payload;

int init_ctr(uint32_t block[4], uint64_t iv) {
	memset(block, 0, sizeof(uint32_t) * 4);

	block[0] = 0xffffffff;
	memcpy(&block[1], &iv, sizeof(uint64_t));
	block[3] = endian32(1);

	return 0;
}

static void _aes_ctr_encrypt(ESP* esp, size_t size, SA_ESP* sa) {
	AES_Ctr_Payload* payload = (AES_Ctr_Payload*)esp->payload;

	uint64_t iv[2];
	RAND_bytes((unsigned char*)(&iv), 16);
	memcpy(payload->iv, &iv, 16);
	unsigned int num = 0;
	uint8_t ecount[16];
	memset(ecount, 0, 16);

	AES_ctr128_encrypt((const unsigned char *)payload->ep,
			(unsigned char *)payload->ep,
			size, ((SA_ESP*)sa)->encrypt_key, (unsigned char*)payload->iv, ecount, &num);
}

static void _aes_ctr_decrypt(ESP* esp, size_t size, SA_ESP* sa) {
//	AES_Ctr_Payload* payload = (AES_Ctr_Payload*)esp->payload;
//
//	char text[17] = "Single block msg";
//	unsigned char aes_key[] = {0xae, 0x68, 0x52, 0xf8, 0x12, 0x10, 0x67, 0xcc, 0x4b, 0xf7, 0xa5, 0x76, 0x55, 0x77, 0xf3, 0x9e};

	//unsigned char block[] = {0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
//	uint32_t block[4];
//	printf("iv: %lx\n", esp->iv | 0xff00000000000000);
//	init_ctr(block, endian64(esp->iv | 0xff00000000000000));
//	printf("\n");
//	char* _block = (char*)block;
//	for(int i = 0; i < 16; i++) {
//		printf("%02x ", _block[i] & 0xff);
//	}
//	printf("\n");
//	AES_encrypt((const unsigned char*)block, (unsigned char*)block, ((SA_ESP*)sa)->decrypt_key);
//
//	for(int i = 0 ;i < 16;i++) {
//		*(esp->payload + i) = *(esp->payload + i) ^ _block[i];
//		printf("%02x ", *(esp->payload + i) & 0xff);
//	}
//	printf("\n");

//	printf("plain: ");
//	for(int i = 0; i < 16; i++) {
//		printf("%02x ", text[i] & 0xff);
//	}
//	printf("\n");
//	printf("key stream: ");
//	for(int i = 0; i < 16; i++) {
//		printf("%02x ", block[i] & 0xff);
//	}
//	printf("\n");
//	for(int i = 0; i < 16; i++) {
//		text[i] ^= block[i];
//	}
//	printf("encrypt: ");
//	for(int i = 0; i < 16; i++) {
//		printf("%02x ", text[i] & 0xff);
//	}
//	printf("\n");
//	for(int i = 0; i < 16; i++) {
//		text[i] ^= block[i];
//	}
//	printf("\n");
//	printf("decrypt: ");
//	for(int i = 0; i < 16; i++) {
//		printf("%02x ", text[i] & 0xff);
//	}
//	printf("\n");

//	unsigned char ecount[AES_BLOCK_SIZE];
//	init_ctr(&ctrstate, esp->iv);
////	AES_ctr128_encrypt((const unsigned char *)esp->payload, 
////			(unsigned char *)esp->payload, 
////			size, ((SA_ESP*)sa)->decrypt_key, ctrstate.ivec, ctrstate.ecount, &ctrstate.num);
//	AES_encrypt(ctrstate.ivec, ecount, ((SA_ESP*)sa)->decrypt_key);
//	for(int i = 0 ;i < 16;i++) {
//		*(esp->payload + i) = *(esp->payload + i) ^ ecount[i];
//		printf("%02x ", *(esp->payload + i) & 0xff);
//	}
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
			size, ((SA_ESP*)sa)->encrypt_key, (unsigned char *)iv, CAMELLIA_ENCRYPT);
}

static void _camellia_cbc_decrypt(ESP* esp, size_t size, SA_ESP* sa) {
	Camellia_CBC_Payload* payload = (Camellia_CBC_Payload*)esp->payload;

	Camellia_cbc_encrypt((const unsigned char *)payload->ep, 
			(unsigned char *)payload->ep, 
			size, ((SA_ESP*)sa)->decrypt_key, (unsigned char *)payload->iv, CAMELLIA_DECRYPT);
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
		.iv_len = 16
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

