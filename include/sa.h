#ifndef __SA_H__
#define __SA_H__
#include <linux/pfkeyv2.h>
#include <linux/ipsec.h>
#include <netinet/in.h>
#include <stdint.h>

// typedef enum {
// 	SA_NONE,
// 	SA_IPSEC_MODE,
// 	SA_TUNNEL_SOURCE_IP,
// 	SA_TUNNEL_DESTINATION_IP,
// 	SA_SPI,
// 	SA_PROTOCOL,
// 	SA_SOURCE_IP,
// 	SA_SOURCE_MASK,
// 	SA_DESTINATION_IP,
// 	SA_DESTINATION_MASK,
// 	SA_SOURCE_PORT,
// 	SA_DESTINATION_PORT,
// 
// 	SA_CRYPTO_ALGORITHM,
// 	SA_CRYPTO_KEY,
// 	SA_CRYPTO_KEY_LENGTH,
// 	SA_IV_SUPPORT,
// 	SA_AUTH_ALGORITHM,
// 	SA_AUTH_KEY,
// 	SA_AUTH_KEY_LENGTH,
// 
// 	SA_REPLY,
// } SA_ATTRIBUTES;

typedef struct _SA {
	struct sadb_msg* sadb_msg;
	struct sadb_sa* sa;
	struct sadb_lifetime* lifetime_current; //current
	struct sadb_lifetime* lifetime_hard; //hard
	struct sadb_lifetime* lifetime_soft; //soft
	struct sadb_address* address_src; //source
	struct sadb_address* address_dst; //destination
	struct sadb_address* address_proxy; //proxy
	struct sadb_key* key_auth; //authentication key
	struct sadb_key* key_encrypt; //encryption key
	struct sadb_ident* identity_src;
	struct sadb_ident* identity_dst;
	struct sadb_sens* sensitivity;
	struct sadb_x_sa2* x_sa2;
	uint8_t data[0];
// 	
// 
// 	uint8_t ipsec_protocol;
// 	uint8_t ipsec_mode;
// 	uint32_t t_src_ip;
// 	uint32_t t_dest_ip;
// 	uint32_t spi;
// 	uint32_t src_ip;
// 	uint32_t src_mask;
// 	uint32_t dest_ip;
// 	uint32_t dest_mask;
// 	uint16_t src_port;
// 	uint16_t dest_port; 
// 	uint8_t protocol; 
// 	uint32_t lifetime; //not working
//  	Window* window;
// 
// 	struct _SA* next;
}__attribute__ ((packed)) SA;

SA* sa_alloc(int data_size);
void sa_free(SA* sa);
void sa_dump(SA* sa);

// typedef struct _SA_ESP {
// 	SA sa;
// 	uint64_t iv;
// 	uint8_t crypto_algorithm;
// 	uint64_t* crypto_key;
// 	uint16_t crypto_key_length;
// 	void* encrypt_key;
// 	void* decrypt_key;
// 
// 	uint8_t auth_algorithm;
// 	uint64_t* auth_key;
// 	uint16_t auth_key_length;
// } SA_ESP;
// 
// typedef struct _SA_AH {
// 	SA sa;
// 	uint8_t auth_algorithm;
// 	uint64_t* auth_key;
// 	uint16_t auth_key_length;
// } SA_AH;

//SA* sa_alloc(NIC* nic, uint64_t* attrs);
#endif /* __SA_H__ */
