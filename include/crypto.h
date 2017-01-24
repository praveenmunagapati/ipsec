#ifndef __CRYPTO_H__
#define __CRYPTO_H__

int crypto_get_iv_len(uint8_t algorithm);
void crypto_encrypt(uint8_t algorithm, uint8_t* payload, uint16_t len, uint8_t* key, uint16_t key_len);
void crypto_decrypt(uint8_t algorithm, uint8_t* payload, uint16_t len, uint8_t* key, uint16_t key_len);
#endif 
