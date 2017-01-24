#include <string.h>

#include <openssl/des.h>
#include <openssl/blowfish.h>
#include <openssl/cast.h>
#include <openssl/aes.h>
#include <openssl/camellia.h>
#include <openssl/rand.h>

#include <util/types.h>
#include <linux/pfkeyv2.h>
#include <byteswap.h>

typedef struct _DES_Payload {
	uint64_t iv;
	uint8_t ep[0]; //encrypted payload
} __attribute__ ((packed)) DES_Payload;

void _des_cbc_encrypt(uint8_t* payload, uint16_t len, uint8_t* key, uint16_t key_len) {
	DES_key_schedule ks;
	DES_set_key_checked((DES_cblock*)key, &ks);
	DES_Payload* des_payload = (DES_Payload*)payload;

	uint64_t iv;
	RAND_bytes((unsigned char*)(&iv), 8);
	des_payload->iv = iv;

	DES_ncbc_encrypt((const unsigned char *)des_payload->ep, 
			(unsigned char *)des_payload->ep,
			len - sizeof(DES_Payload), &ks, (unsigned char(*)[8])&iv, DES_ENCRYPT);
}

static void _des_cbc_decrypt(uint8_t* payload, uint16_t len, uint8_t* key, uint16_t key_len) {
	DES_key_schedule ks;
	DES_set_key_checked((DES_cblock*)key, &ks);
	DES_Payload* des_payload = (DES_Payload*)payload;

	DES_ncbc_encrypt((const unsigned char *)des_payload->ep, 
			(unsigned char *)des_payload->ep,
			len - sizeof(DES_Payload), &ks, (unsigned char(*)[8])&(des_payload->iv), DES_DECRYPT);
}

typedef struct __3DES_Payload {
	uint64_t iv;
	uint8_t ep[0]; //encrypted payload
} __attribute__ ((packed)) _3DES_Payload;

void _3des_cbc_encrypt(uint8_t* payload, uint16_t len, uint8_t* key, uint16_t key_len) {
	DES_key_schedule ks[3];
	DES_cblock* des_cblock = (void*)key; //Why?
	for(int i = 0; i < 3; i++) {
		DES_set_key_checked(&des_cblock[i], &ks[i]);
	}
	_3DES_Payload* _3des_payload = (_3DES_Payload*)payload;

	uint64_t iv;
	RAND_bytes((unsigned char*)(&iv), 8);
	_3des_payload->iv = iv;

	DES_ede3_cbc_encrypt((const unsigned char*)_3des_payload->ep,
			(unsigned char*)_3des_payload->ep, 
			len - sizeof(_3DES_Payload), &ks[0], &ks[1], &ks[2], (unsigned char(*)[8])&iv, DES_ENCRYPT);
}

void _3des_cbc_decrypt(uint8_t* payload, uint16_t len, uint8_t* key, uint16_t key_len) {
	DES_key_schedule ks[3];
	DES_cblock* des_cblock = (void*)key; //Why?
	for(int i = 0; i < 3; i++) {
		DES_set_key_checked(&des_cblock[i], &ks[i]);
	}
	
	_3DES_Payload* _3des_payload = (_3DES_Payload*)payload;

	//DES_key_schedule* ks_3 = (DES_key_schedule*)key;
	DES_ede3_cbc_encrypt((const unsigned char*)_3des_payload->ep, 
			(unsigned char*)_3des_payload->ep, 
			len - sizeof(_3DES_Payload), &ks[0], &ks[1], &ks[2], (unsigned char(*)[8])&(_3des_payload->iv), DES_DECRYPT);
}

typedef struct _Blowfish_Payload {
	uint64_t iv;
	uint8_t ep[0]; //encrypted payload
} __attribute__ ((packed)) Blowfish_Payload;

void _blowfish_cbc_encrypt(uint8_t* payload, uint16_t len, uint8_t* key, uint16_t key_len) {
	BF_KEY bf_key;
	BF_set_key(&bf_key, key_len, (const unsigned char*)key);
	Blowfish_Payload* blowfish_payload = (Blowfish_Payload*)payload;

	uint64_t iv;
	RAND_bytes((unsigned char*)(&iv), 8);
	blowfish_payload->iv = iv;
	
	BF_cbc_encrypt((const unsigned char *)blowfish_payload->ep, 
			(unsigned char *)blowfish_payload->ep, 
			len - sizeof(Blowfish_Payload), &bf_key, (unsigned char*)(&iv), BF_ENCRYPT);
}

void _blowfish_cbc_decrypt(uint8_t* payload, uint16_t len, uint8_t* key, uint16_t key_len) {
	BF_KEY bf_key;
	BF_set_key(&bf_key, key_len, (const unsigned char*)key);
	Blowfish_Payload* blowfish_payload = (Blowfish_Payload*)payload;

	BF_cbc_encrypt((const unsigned char *)blowfish_payload->ep, 
			(unsigned char *)blowfish_payload->ep, 
			len - sizeof(Blowfish_Payload), &bf_key, (unsigned char*)(&(blowfish_payload->iv)), BF_DECRYPT);
}

typedef struct _Cast128_Payload {
	uint64_t iv;
	uint8_t ep[0]; //encrypted payload
} __attribute__ ((packed)) Cast128_Payload;

void _cast128_cbc_encrypt(uint8_t* payload, uint16_t len, uint8_t* key, uint16_t key_len) {
	CAST_KEY cast_key;
	CAST_set_key(&cast_key, key_len, (const unsigned char*)key);
	Cast128_Payload* cast128_payload = (Cast128_Payload*)payload;

	uint64_t iv;
	RAND_bytes((unsigned char*)(&iv), 8);
	cast128_payload->iv = iv;

	CAST_cbc_encrypt((const unsigned char *)cast128_payload->ep,
			(unsigned char *)cast128_payload->ep,
			len - sizeof(Cast128_Payload), &cast_key, (unsigned char *)&iv, CAST_ENCRYPT);
}

void _cast128_cbc_decrypt(uint8_t* payload, uint16_t len, uint8_t* key, uint16_t key_len) {
	CAST_KEY cast_key;
	CAST_set_key(&cast_key, key_len, (const unsigned char*)key);
	Cast128_Payload* cast128_payload = (Cast128_Payload*)payload;

	CAST_cbc_encrypt((const unsigned char *)cast128_payload->ep, 
			(unsigned char *)cast128_payload->ep, 
			len - sizeof(Cast128_Payload), &cast_key, (unsigned char *)(&(cast128_payload->iv)), CAST_DECRYPT);
}

typedef struct _Rijndael_CBC_Payload {
	uint64_t iv[2];
	uint8_t ep[0]; //encrypted payload
} __attribute__ ((packed)) Rijndael_CBC_Payload;

void _rijndael_cbc_encrypt(uint8_t* payload, uint16_t len, uint8_t* key, uint16_t key_len) {
	AES_KEY aes_key;
	AES_set_encrypt_key((const unsigned char*)key, key_len * 8, &aes_key);
	Rijndael_CBC_Payload* rijndael_payload = (Rijndael_CBC_Payload*)payload;

	uint64_t iv[2];
	RAND_bytes((unsigned char*)(&iv), 16);
	memcpy(rijndael_payload->iv, iv, 16);
	
	AES_cbc_encrypt((const unsigned char *)rijndael_payload->ep,
			(unsigned char *)rijndael_payload->ep,
			len - sizeof(Rijndael_CBC_Payload), &aes_key, (unsigned char *)(&iv), AES_ENCRYPT);
}

void _rijndael_cbc_decrypt(uint8_t* payload, uint16_t len, uint8_t* key, uint16_t key_len) {
	AES_KEY aes_key;
	AES_set_decrypt_key((const unsigned char*)key, key_len * 8, &aes_key);
	Rijndael_CBC_Payload* rijndael_payload = (Rijndael_CBC_Payload*)payload;

	AES_cbc_encrypt((const unsigned char *)rijndael_payload->ep, 
			(unsigned char *)rijndael_payload->ep, 
			len - sizeof(Rijndael_CBC_Payload), &aes_key, (unsigned char*)(&(rijndael_payload->iv)), AES_DECRYPT);
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

static int init_ctr_block(uint32_t block[4], uint32_t nonce, uint64_t iv, uint32_t num) {
	memset(block, 0, sizeof(uint32_t) * 4);

	block[0] = nonce;
	memcpy(&block[1], &iv, 8);
	block[3] = bswap_32(num);

	return 0;
}

static uint32_t get_nonce(uint8_t* key, uint16_t key_len) {
	uint32_t* nonce;
	nonce = (uint32_t*)(key + key_len - 4);

	return *nonce;
}

void _aes_ctr_encrypt(uint8_t* payload, uint16_t len, uint8_t* key, uint16_t key_len) {
	AES_KEY aes_key;
	printf("key len %d\n", key_len);
	AES_set_encrypt_key((const unsigned char*)key, (key_len - 4) * 8, &aes_key);
	AES_CTR_Payload* aes_payload = (AES_CTR_Payload*)payload;

	uint64_t iv;
	RAND_bytes((unsigned char*)(&iv), 8);
	aes_payload->iv = iv;

	uint8_t ctr_block[16];
	uint32_t nonce = get_nonce(key, key_len);
	len -= sizeof(AES_CTR_Payload);
	uint8_t* ep = aes_payload->ep;
	for(int i = 1; len > 0; i++) {
		init_ctr_block((uint32_t*)ctr_block, nonce, aes_payload->iv, i);

		AES_encrypt((const unsigned char*)ctr_block, (unsigned char*)ctr_block, &aes_key);

		for(int j = 0; j < 16 && len > 0; j++, len--) {
			*ep ^= ctr_block[j];
			ep++;
		}
	}
}

void _aes_ctr_decrypt(uint8_t* payload, uint16_t len, uint8_t* key, uint16_t key_len) {
	AES_KEY aes_key;
	AES_set_encrypt_key((const unsigned char*)key, (key_len - 4) * 8, &aes_key);
	AES_CTR_Payload* aes_payload = (AES_CTR_Payload*)payload;

	uint8_t ctr_block[16];
	uint32_t nonce = get_nonce(key, key_len);
	len -= sizeof(AES_CTR_Payload);
	uint8_t* ep = aes_payload->ep;
	for(int i = 1; len > 0; i++) {
		init_ctr_block((uint32_t*)ctr_block, nonce, aes_payload->iv, i);

		AES_encrypt((const unsigned char*)ctr_block, (unsigned char*)ctr_block, &aes_key);

		for(int j = 0 ;j < 16 && len > 0; j++, len--) {
			*ep ^= ctr_block[j];
			ep++;
		}
	}
}

// TODO : 16 Byte Alighment for Payload
// Key Length : 16, 24, 32 Bytes (Default : 16 Bytes)
typedef struct _Camellia_CBC_Payload {
	uint64_t iv[2];
	uint8_t ep[0]; //encrypted payload
} __attribute__ ((packed)) Camellia_CBC_Payload;

void _camellia_cbc_encrypt(uint8_t* payload, uint16_t len, uint8_t* key, uint16_t key_len) {
	CAMELLIA_KEY camellia_key;
	Camellia_set_key(key, key_len * 8, &camellia_key);
	Camellia_CBC_Payload* camellia_payload = (Camellia_CBC_Payload*)payload;

	uint64_t iv[2];
	RAND_bytes((unsigned char*)(&iv), 16);
	memcpy(camellia_payload->iv, iv, 16);
	
	Camellia_cbc_encrypt((const unsigned char *)camellia_payload->ep,
			(unsigned char *)camellia_payload->ep,
			len - sizeof(Camellia_CBC_Payload), &camellia_key, (unsigned char *)iv, CAMELLIA_ENCRYPT);
}

void _camellia_cbc_decrypt(uint8_t* payload, uint16_t len, uint8_t* key, uint16_t key_len) {
	CAMELLIA_KEY camellia_key;
	Camellia_set_key(key, key_len * 8, &camellia_key);
	Camellia_CBC_Payload* camellia_payload = (Camellia_CBC_Payload*)payload;

	Camellia_cbc_encrypt((const unsigned char *)camellia_payload->ep, 
			(unsigned char *)camellia_payload->ep, 
			len - sizeof(Camellia_CBC_Payload), &camellia_key, (unsigned char *)camellia_payload->iv, CAMELLIA_DECRYPT);
}

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
			return 0;
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
