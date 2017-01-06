#include <util/types.h>
#include <linux/pfkeyv2.h>
#include <stdio.h>

#include "crypto.h"

// Key Length : 8 Bytes
typedef struct _DES_Payload {
	uint64_t iv;
	uint8_t ep[0]; //encrypted payload
} __attribute__ ((packed)) DES_Payload;

inline void _des_cbc_encrypt(uint8_t* payload, uint16_t len, uint8_t* key, uint16_t key_len) {
	DES_Payload* des_payload = (DES_Payload*)payload;

	uint64_t iv;
	RAND_bytes((unsigned char*)(&iv), 8);
	des_payload->iv = iv;

	DES_ncbc_encrypt((const unsigned char *)des_payload->ep, 
			(unsigned char *)des_payload->ep,
			len - sizeof(DES_Payload), (DES_key_schedule*)key, (unsigned char(*)[8])&iv, DES_ENCRYPT);
}

static void _des_cbc_decrypt(uint8_t* payload, uint16_t len, uint8_t* key, uint16_t key_len) {
	DES_Payload* des_payload = (DES_Payload*)payload;

	DES_ncbc_encrypt((const unsigned char *)des_payload->ep, 
			(unsigned char *)des_payload->ep,
			len - sizeof(DES_Payload), (DES_key_schedule*)key, (unsigned char(*)[8])&(des_payload->iv), DES_DECRYPT);
}

// Key Length : 24 Bytes
typedef struct __3DES_Payload {
	uint64_t iv;
	uint8_t ep[0]; //encrypted payload
} __attribute__ ((packed)) _3DES_Payload;

inline void _3des_cbc_encrypt(uint8_t* payload, uint16_t len, uint8_t* key, uint16_t key_len) {
	_3DES_Payload* _3des_payload = (_3DES_Payload*)payload;

	uint64_t iv;
	RAND_bytes((unsigned char*)(&iv), 8);
	_3des_payload->iv = iv;

	DES_key_schedule* ks_3 = (DES_key_schedule*)key;
	DES_ede3_cbc_encrypt((const unsigned char*)_3des_payload->ep,
			(unsigned char*)_3des_payload->ep, 
			len - sizeof(_3DES_Payload), &ks_3[0], &ks_3[1], &ks_3[2], (unsigned char(*)[8])&iv, DES_ENCRYPT);
}

inline void _3des_cbc_decrypt(uint8_t* payload, uint16_t len, uint8_t* key, uint16_t key_len) {
	_3DES_Payload* _3des_payload = (_3DES_Payload*)payload;

	DES_key_schedule* ks_3 = (DES_key_schedule*)key;
	DES_ede3_cbc_encrypt((const unsigned char*)_3des_payload->ep, 
			(unsigned char*)_3des_payload->ep, 
			len - sizeof(_3DES_Payload), &ks_3[0], &ks_3[1], &ks_3[2], (unsigned char(*)[8])&(_3des_payload->iv), DES_DECRYPT);
}


// Key Length : 5 ~ 56 Bytes (Default : 16 Bytes)
typedef struct _Blowfish_Payload {
	uint64_t iv;
	uint8_t ep[0]; //encrypted payload
} __attribute__ ((packed)) Blowfish_Payload;

inline void _blowfish_cbc_encrypt(uint8_t* payload, uint16_t len, uint8_t* key, uint16_t key_len) {
	Blowfish_Payload* blowfish_payload = (Blowfish_Payload*)payload;

	uint64_t iv;
	RAND_bytes((unsigned char*)(&iv), 8);
	blowfish_payload->iv = iv;
	
	BF_cbc_encrypt((const unsigned char *)blowfish_payload->ep, 
			(unsigned char *)blowfish_payload->ep, 
			len - sizeof(Blowfish_Payload), (BF_KEY*)key, (unsigned char*)(&iv), BF_ENCRYPT);
}

inline void _blowfish_cbc_decrypt(uint8_t* payload, uint16_t len, uint8_t* key, uint16_t key_len) {
	Blowfish_Payload* blowfish_payload = (Blowfish_Payload*)payload;

	BF_cbc_encrypt((const unsigned char *)blowfish_payload->ep, 
			(unsigned char *)blowfish_payload->ep, 
			len - sizeof(Blowfish_Payload), (BF_KEY*)key, (unsigned char*)(&(blowfish_payload->iv)), BF_DECRYPT);
}

// Key Length : 5 ~ 56 Bytes (Default : 16 Bytes)
typedef struct _Cast128_Payload {
	uint64_t iv;
	uint8_t ep[0]; //encrypted payload
} __attribute__ ((packed)) Cast128_Payload;

inline void _cast128_cbc_encrypt(uint8_t* payload, uint16_t len, uint8_t* key, uint16_t key_len) {
	Cast128_Payload* cast128_payload = (Cast128_Payload*)payload;

	uint64_t iv;
	RAND_bytes((unsigned char*)(&iv), 8);
	cast128_payload->iv = iv;

	CAST_cbc_encrypt((const unsigned char *)cast128_payload->ep,
			(unsigned char *)cast128_payload->ep,
			len - sizeof(Cast128_Payload), (CAST_KEY*)key, (unsigned char *)&iv, CAST_ENCRYPT);
}

inline void _cast128_cbc_decrypt(uint8_t* payload, uint16_t len, uint8_t* key, uint16_t key_len) {
	Cast128_Payload* cast128_payload = (Cast128_Payload*)payload;

	CAST_cbc_encrypt((const unsigned char *)cast128_payload->ep, 
			(unsigned char *)cast128_payload->ep, 
			len - sizeof(Cast128_Payload), (CAST_KEY*)key, (unsigned char *)(&(cast128_payload->iv)), CAST_DECRYPT);
}

// static void _des_deriv_encrypt(ESP* esp, size_t size, SA_ESP* sa){
// }
// 
// static void _des_deriv_decrypt(ESP* esp, size_t size, SA_ESP* sa){
// }
// 
// static void _3des_deriv_encrypt(ESP* esp, size_t size, SA_ESP* sa){
// }
// 
// static void _3des_deriv_decrypt(ESP* esp, size_t size, SA_ESP* sa){
// }
// 
// // TODO : 16 Byte Alighment for Payload
// Key Length : 16, 24, 32 Bytes (Default : 16 Bytes)
typedef struct _Rijndael_CBC_Payload {
	uint64_t iv[2];
	uint8_t ep[0]; //encrypted payload
} __attribute__ ((packed)) Rijndael_CBC_Payload;

inline void _rijndael_cbc_encrypt(uint8_t* payload, uint16_t len, uint8_t* key, uint16_t key_len) {
	Rijndael_CBC_Payload* rijndael_payload = (Rijndael_CBC_Payload*)payload;

	uint64_t iv[2];
	RAND_bytes((unsigned char*)(&iv), 16);
	memcpy(rijndael_payload->iv, iv, 16);
	
	AES_cbc_encrypt((const unsigned char *)rijndael_payload->ep,
			(unsigned char *)rijndael_payload->ep,
			len - sizeof(Rijndael_CBC_Payload), (AES_KEY*)key, (unsigned char *)(&iv), AES_ENCRYPT);
}

inline void _rijndael_cbc_decrypt(uint8_t* payload, uint16_t len, uint8_t* key, uint16_t key_len) {
	Rijndael_CBC_Payload* rijndael_payload = (Rijndael_CBC_Payload*)payload;

	AES_cbc_encrypt((const unsigned char *)rijndael_payload->ep, 
			(unsigned char *)rijndael_payload->ep, 
			len - sizeof(Rijndael_CBC_Payload), (AES_KEY*)key, (unsigned char*)(&(rijndael_payload->iv)), AES_DECRYPT);
}

/*
   Not implemented : No openssl function 

   AES and Triple DES are considered to be strong. Blowfish is still a good algorithm but its author (Bruce Schneier) recommends that you should use the "twofish" algorithm instead if available. Unfortunately twofish is not yet available in the list of openssl ciphers.
*/
// typedef struct _TwoFish_Payload {
// 	uint64_t iv[2];
// 	uint8_t ep[0]; //encrypted payload
// } __attribute__ ((packed)) TwoFish_Payload;
// 
// static void _twofish_cbc_encrypt(ESP* esp, size_t size, void* key) {
// }
// 
// static void _twofish_cbc_decrypt(ESP* esp, size_t size, void* key) {
// }

// Key Length : 16, 24, 32 Bytes (Default : 16 Bytes) Nonce : 4 Bytes
typedef struct _AES_CTR_Payload {
	uint64_t iv;
	uint8_t ep[0]; //encrypted payload
} __attribute__ ((packed)) AES_CTR_Payload;

inline int init_ctr_block(uint32_t block[4], uint32_t nonce, uint64_t iv, uint32_t num) {
	memset(block, 0, sizeof(uint32_t) * 4);

	block[0] = nonce;
	memcpy(&block[1], &iv, 8);
	block[3] = endian32(num);

	return 0;
}

inline uint32_t get_nonce(void* key, uint16_t key_len) {
	uint32_t* nonce;
	nonce = (uint32_t*)(key + key_len - 4);

	return *nonce;
}

inline void _aes_ctr_encrypt(uint8_t* payload, uint16_t len, uint8_t* key, uint16_t key_len) {
	AES_CTR_Payload* aes_payload = (AES_CTR_Payload*)payload;

	uint64_t iv;
	RAND_bytes((unsigned char*)(&iv), 8);
	memcpy(&(aes_payload->iv), &iv, 8);

	uint8_t ctr_block[16];
	//TODO set_key_len
	uint32_t nonce = get_nonce(key, key_len);
	for(int i = 1; (i - 1) * 16 < len - sizeof(AES_CTR_Payload); i++) {
		init_ctr_block((uint32_t*)ctr_block, nonce, aes_payload->iv, i);

		AES_encrypt((const unsigned char*)ctr_block, (unsigned char*)ctr_block, (AES_KEY*)key);

		for(int j = 0 ;j < 16 && ((i - 1) * 16 + j) < len - sizeof(AES_CTR_Payload); j++) {
			*(((uint8_t*)aes_payload->ep + ((i - 1) * 16) + j)) ^= ctr_block[j];
		}
	}
}

inline void _aes_ctr_decrypt(uint8_t* payload, uint16_t len, uint8_t* key, uint16_t key_len) {
	AES_CTR_Payload* aes_payload = (AES_CTR_Payload*)payload;

	uint8_t ctr_block[16];
	//TODO set_key_len
	uint32_t nonce = get_nonce(key, key_len);
	for(int i = 1; (i - 1) * 16 < len - sizeof(AES_CTR_Payload); i++) {
		init_ctr_block((uint32_t*)ctr_block, nonce, aes_payload->iv, i);

		AES_encrypt((const unsigned char*)ctr_block, (unsigned char*)ctr_block, (AES_KEY*)key);

		for(int j = 0 ;j < 16 && ((i - 1) * 16 + j) < len - sizeof(AES_CTR_Payload); j++) {
			*(((uint8_t*)aes_payload->ep + ((i - 1) * 16) + j)) ^= ctr_block[j];
		}
	}
}

// TODO : 16 Byte Alighment for Payload
// Key Length : 16, 24, 32 Bytes (Default : 16 Bytes)
typedef struct _Camellia_CBC_Payload {
	uint64_t iv[2];
	uint8_t ep[0]; //encrypted payload
} __attribute__ ((packed)) Camellia_CBC_Payload;

inline void _camellia_cbc_encrypt(uint8_t* payload, uint16_t len, uint8_t* key, uint16_t key_len) {
	Camellia_CBC_Payload* camellia_payload = (Camellia_CBC_Payload*)payload;

	uint64_t iv[2];
	RAND_bytes((unsigned char*)(&iv), 16);
	memcpy(camellia_payload->iv, iv, 16);
	
	Camellia_cbc_encrypt((const unsigned char *)camellia_payload->ep,
			(unsigned char *)camellia_payload->ep,
			len - sizeof(Camellia_CBC_Payload), (CAMELLIA_KEY*)key, (unsigned char *)iv, CAMELLIA_ENCRYPT);
}

inline void _camellia_cbc_decrypt(uint8_t* payload, uint16_t len, uint8_t* key, uint16_t key_len) {
	Camellia_CBC_Payload* camellia_payload = (Camellia_CBC_Payload*)payload;

	Camellia_cbc_encrypt((const unsigned char *)camellia_payload->ep, 
			(unsigned char *)camellia_payload->ep, 
			len - sizeof(Camellia_CBC_Payload), (CAMELLIA_KEY*)key, (unsigned char *)camellia_payload->iv, CAMELLIA_DECRYPT);
}
// 
// Cryptography cryptographys[] = {
// 	{
// 		.encrypt = _des_cbc_encrypt,
// 		.decrypt = _des_cbc_decrypt,
// 		.iv_len = 8
// 	},
// 	{
// 		.encrypt = _3des_cbc_encrypt,
// 		.decrypt = _3des_cbc_decrypt,
// 		.iv_len = 8
// 	},
// 	{
// 		.encrypt = _blowfish_cbc_encrypt,
// 		.decrypt = _blowfish_cbc_decrypt,
// 		.iv_len = 8
// 	},
// 	{
// 		.encrypt = _cast128_cbc_encrypt,
// 		.decrypt = _cast128_cbc_decrypt,
// 		.iv_len = 8
// 	},
// 	{
// 		.encrypt = _des_deriv_encrypt,
// 		.decrypt = _des_deriv_decrypt,
// 		.iv_len = 8
// 	},
// 	{
// 		.encrypt = _3des_deriv_encrypt,
// 		.decrypt = _3des_deriv_decrypt,
// 		.iv_len = 8
// 	},
// 	{
// 		.encrypt = _rijndael_cbc_encrypt,
// 		.decrypt = _rijndael_cbc_decrypt,
// 		.iv_len = 16
// 	},
// 	{
// 		.encrypt = _twofish_cbc_encrypt,
// 		.decrypt = _twofish_cbc_decrypt,
// 		.iv_len = 16
// 	},
// 	{
// 		.encrypt = _aes_ctr_encrypt,
// 		.decrypt = _aes_ctr_decrypt,
// 		.iv_len = 8
// 	},
// 	{
// 		.encrypt = _camellia_cbc_encrypt,
// 		.decrypt = _camellia_cbc_decrypt,
// 		.iv_len = 16
// 	},
// };

//TODO check iv_len each algorithm
int crypto_get_iv_len(uint8_t algorithm) {
	switch(algorithm) {
		case SADB_EALG_NONE:	       
			return 0;
		case SADB_EALG_DESCBC:	       
			return 8;
		case SADB_EALG_3DESCBC:	       
			return 8;
		case SADB_X_EALG_CASTCBC:       
			return 8;
		case SADB_X_EALG_BLOWFISHCBC:   
			return 8;
		case SADB_EALG_NULL:	       
			return 8;
		case SADB_X_EALG_AESCBC:	       
			return 16;
		case SADB_X_EALG_AESCTR:	       
			return 8;
		case SADB_X_EALG_AES_CCM_ICV8:  
			return 8;
		case SADB_X_EALG_AES_CCM_ICV12: 
			return 12;
		case SADB_X_EALG_AES_CCM_ICV16: 
			return 16;
		case SADB_X_EALG_AES_GCM_ICV8:  
			return 8;
		case SADB_X_EALG_AES_GCM_ICV12: 
			return 12;
		case SADB_X_EALG_AES_GCM_ICV16: 
			return 16;
		case SADB_X_EALG_CAMELLIACBC:   
			return 16;
		case SADB_X_EALG_NULL_AES_GMAC:
			return 8;
		case SADB_X_EALG_SERPENTCBC:
			return 8;
		case SADB_X_EALG_TWOFISHCBC: 
			return 16;
	}

	return 0;
}

void crypto_encrypt(uint8_t algorithm, uint8_t* payload, uint16_t len, uint8_t* key, uint16_t key_len) {
	switch(algorithm) {
		case SADB_EALG_NONE:	       
			return;
		case SADB_EALG_DESCBC:	       
			_des_cbc_encrypt(payload, len, key, key_len);
			return;
		case SADB_EALG_3DESCBC:	       
			_3des_cbc_encrypt(payload, len, key, key_len);
			return;
		case SADB_X_EALG_CASTCBC:       
			_cast128_cbc_encrypt(payload, len, key, key_len);
			return;
		case SADB_X_EALG_BLOWFISHCBC:   
			_blowfish_cbc_encrypt(payload, len, key, key_len);
			return;
		case SADB_EALG_NULL:	       
			return;
		case SADB_X_EALG_AESCBC:	       
			//?? rijndael???
			_rijndael_cbc_encrypt(payload, len, key, key_len);
			return;
		case SADB_X_EALG_AESCTR:	       
			_aes_ctr_encrypt(payload, len, key, key_len);
			return;
		case SADB_X_EALG_AES_CCM_ICV8:  
			return;
		case SADB_X_EALG_AES_CCM_ICV12: 
			return;
		case SADB_X_EALG_AES_CCM_ICV16: 
			return;
		case SADB_X_EALG_AES_GCM_ICV8:  
			return;
		case SADB_X_EALG_AES_GCM_ICV12: 
			return;
		case SADB_X_EALG_AES_GCM_ICV16: 
			return;
		case SADB_X_EALG_CAMELLIACBC:   
			_camellia_cbc_encrypt(payload, len, key, key_len);
			return;
		case SADB_X_EALG_NULL_AES_GMAC:
			return;
		case SADB_X_EALG_SERPENTCBC:
			return;
		case SADB_X_EALG_TWOFISHCBC: 
			return;
	}
}

void crypto_decrypt(uint8_t algorithm, uint8_t* payload, uint16_t len, uint8_t* key, uint16_t key_len) {
	switch(algorithm) {
		case SADB_EALG_NONE:	       
			return;
		case SADB_EALG_DESCBC:	       
			_des_cbc_decrypt(payload, len, key, key_len);
			return;
		case SADB_EALG_3DESCBC:	       
			_3des_cbc_decrypt(payload, len, key, key_len);
			return;
		case SADB_X_EALG_CASTCBC:       
			_cast128_cbc_decrypt(payload, len, key, key_len);
			return;
		case SADB_X_EALG_BLOWFISHCBC:   
			_blowfish_cbc_decrypt(payload, len, key, key_len);
			return;
		case SADB_EALG_NULL:	       
			return;
		case SADB_X_EALG_AESCBC:	       
			_rijndael_cbc_decrypt(payload, len, key, key_len);
			return;
		case SADB_X_EALG_AESCTR:	       
			_aes_ctr_decrypt(payload, len, key, key_len);
			return;
		case SADB_X_EALG_AES_CCM_ICV8:  
			return;
		case SADB_X_EALG_AES_CCM_ICV12: 
			return;
		case SADB_X_EALG_AES_CCM_ICV16: 
			return;
		case SADB_X_EALG_AES_GCM_ICV8:  
			return;
		case SADB_X_EALG_AES_GCM_ICV12: 
			return;
		case SADB_X_EALG_AES_GCM_ICV16: 
			return;
		case SADB_X_EALG_CAMELLIACBC:   
			_camellia_cbc_decrypt(payload, len, key, key_len);
			return;
		case SADB_X_EALG_NULL_AES_GMAC:
			return;
		case SADB_X_EALG_SERPENTCBC:
			return;
		case SADB_X_EALG_TWOFISHCBC: 
			return;
	}
}
