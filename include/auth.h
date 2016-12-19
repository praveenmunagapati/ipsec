#ifndef __AUTH_H__
#define __AUTH_H__

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <net/packet.h>

void auth_request(uint8_t protocol, uint8_t* target, uint8_t* source, uint16_t len, uint8_t* key, uint16_t key_len);
bool auth_check(uint8_t algorithm, uint8_t* target, uint8_t* source, uint16_t len, uint8_t* key, uint8_t key_len);
#endif 
