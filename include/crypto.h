#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include <stdio.h>
#include <string.h>
#include <openssl/des.h>
#include <openssl/blowfish.h>
#include <openssl/cast.h>
#include <openssl/aes.h>
#include <openssl/camellia.h>
#include <openssl/rand.h>
#include <net/ether.h>

#include "sa.h"
#include "esp.h"

int crypto_get_iv_len(uint8_t algorithm);
void crypto_encrypt(uint8_t algorithm, uint8_t* payload, uint16_t len, uint8_t* key, uint16_t key_len);
void crypto_decrypt(uint8_t algorithm, uint8_t* payload, uint16_t len, uint8_t* key, uint16_t key_len);
#endif 
