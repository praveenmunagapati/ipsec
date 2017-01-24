#ifndef __AUTH_H__
#define __AUTH_H__

#include <stdio.h>
#include <stdbool.h>
#include <string.h>

int auth_get_icv_len(uint8_t algorithm);
int auth_get_authdata_len(uint8_t algorithm);
void auth_request(uint8_t algorithm, uint8_t* target, uint16_t t_len, uint8_t* source, uint16_t s_len, uint8_t* key, uint16_t key_len);
bool auth_check(uint8_t algorithm, uint8_t* target, uint16_t t_len, uint8_t* source, uint16_t s_len, uint8_t* key, uint8_t key_len);
#endif 
