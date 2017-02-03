#include <malloc.h>
#define DONT_MAKE_WRAPPER
#include <_malloc.h>
#undef DONT_MAKE_WRAPPER
#include <string.h>
#include <net/ip.h>
#include <byteswap.h>

#include "sa.h"

extern void* __gmalloc_pool;
SA* sa_alloc(int data_size) {
        SA* sa = __malloc(sizeof(SA) + data_size, __gmalloc_pool);
	if(!sa) {
		return NULL;
	}
	memset(sa, 0, sizeof(SA) + data_size);

	return sa;
}

void sa_free(SA* sa) {
	__free(sa, __gmalloc_pool);
}

void sa_dump(SA* sa) {
 	char* print_sadb_auth(uint8_t type) {
 		switch(type) {
 			case SADB_AALG_NONE:
 				return "NONE";
 			case SADB_AALG_MD5HMAC:
 				return "MD5HMAC";
 			case SADB_AALG_SHA1HMAC:
 				return "SHA1MAC";
 			case SADB_X_AALG_SHA2_256HMAC:
 				return "SHA2-256HMAC";
 			case SADB_X_AALG_SHA2_384HMAC:
 				return "SHA2-384HMAC";
 			case SADB_X_AALG_SHA2_512HMAC:
 				return "SHA2-512HMAC";
 			case SADB_X_AALG_RIPEMD160HMAC:
 				return "RIPEMD-160HMAC";
 			case SADB_X_AALG_AES_XCBC_MAC:
 				return "AES-XCBC-MAC";
 			case SADB_X_AALG_NULL:
 				return "NULL";
 			default:
 				return "INVALID";
 		}
 	}
 
 	char* print_sadb_encrypt(uint8_t type) {
 		switch(type) {
 			case SADB_EALG_NONE:
 				return "NONE";
 			case SADB_EALG_DESCBC:
 				return "DES-CBC";
 			case SADB_EALG_3DESCBC:
 				return "3DES-CBC";
 			case SADB_X_EALG_CASTCBC:
 				return "CAST-CBC";
 			case SADB_X_EALG_BLOWFISHCBC:
 				return "BLOWFISH CBC";
 			case SADB_EALG_NULL:
 				return "NULL";
 			case SADB_X_EALG_AESCBC:
 				return "AES-CBC";
 			case SADB_X_EALG_AESCTR:
 				return "AES-CTR";
 			case SADB_X_EALG_AES_CCM_ICV8:
 				return "AES-CCM-ICV8";
 			case SADB_X_EALG_AES_CCM_ICV12:
 				return "AES-CCM-ICV12";
 			case SADB_X_EALG_AES_CCM_ICV16:
 				return "AES-CCM-ICV16";
 			case SADB_X_EALG_AES_GCM_ICV8:
 				return "AES-GCM-ICV8";
 			case SADB_X_EALG_AES_GCM_ICV12:
 				return "AES-GCM-ICV12";
 			case SADB_X_EALG_AES_GCM_ICV16:
 				return "AES-GCM-ICV16";
 			case SADB_X_EALG_CAMELLIACBC:
 				return "CAMELLIA-CBC";
 			case SADB_X_EALG_NULL_AES_GMAC:
 				return "NULL-AES-GMAC";
 			default:
 				return "INVALID";
 		}
 	}
 
 	char* print_ip_protocol(uint8_t protocol) {
 		switch(protocol) {
 			case 0:
 				return "ANY";
 			case IP_PROTOCOL_ICMP:
 				return "ICMP";
 			case IP_PROTOCOL_IP:
 				return "IP";
 			case IP_PROTOCOL_UDP:
 				return "UDP";
 			case IP_PROTOCOL_TCP:	
 				return "TCP";
 			case IP_PROTOCOL_ESP:
 				return "ESP";
 			case IP_PROTOCOL_AH:
 				return "AH";
 			default:
 				return "INVALID";
 		}
 	}
 
 	void print_key(uint8_t* key, int key_len) {
 
 		printf("0x");
 		for(int i = 0; i < key_len; i++) {
 			printf("%02x", key[i] & 0xff);
 		}
 		printf("\n");
 	}
 
 	char* print_mode(uint8_t mode) {
 		switch(mode) {
 			case IPSEC_MODE_ANY:
 				return "ANY";
 			case IPSEC_MODE_TRANSPORT:
 				return "TRANSPORT";
 			case IPSEC_MODE_TUNNEL:
 				return "TUNNEL";
 			case IPSEC_MODE_BEET:
 				return "BEET";
 			default:
 				return "INVALID";
 		}	
 	}
 
 	char* print_sa_type(uint8_t satype) {
 		switch(satype) {
 			case SADB_SATYPE_UNSPEC:
 				return "UNSPEC";
 			case SADB_SATYPE_AH:
 				return "AH";
 			case SADB_SATYPE_ESP:
 				return "ESP";
 			case SADB_SATYPE_RSVP:
 				return "RSVP";
 			case SADB_SATYPE_OSPFV2:
 				return "OSPFV2";
 			case SADB_SATYPE_RIPV2:
 				return "RIPV2";
 			case SADB_SATYPE_MIP:
 				return "MIP";
 			case SADB_X_SATYPE_IPCOMP:
 				return "IPCOMP";
 			default:
 				return "INVALID";
 		}
 	}
 
 	printf("======================================\n");
 	printf("Authotication:\n");
 	printf("\tSA Type:\t%s\n", print_sa_type(sa->sadb_msg->sadb_msg_satype));
 	printf("\tSPI:\t\t0x%x\n", bswap_32(sa->sa->sadb_sa_spi));
 	printf("\tAuth:\t\t%s\n", print_sadb_auth(sa->sa->sadb_sa_auth));
 	printf("\tEncryption:\t%s\n", print_sadb_encrypt(sa->sa->sadb_sa_encrypt));
 	printf("Src Address:\n");
 	printf("\tProtocol:\t%s\n", print_ip_protocol(sa->address_src->sadb_address_proto));
 	struct sockaddr_in* src_sockaddr = (struct sockaddr_in*)((uint8_t*)sa->address_src + sizeof(*sa->address_src));
 	uint8_t* src_addr = (uint8_t*)&(src_sockaddr->sin_addr.s_addr);
 	printf("\tAddress:\t%u.%u.%u.%u/%d\n", src_addr[0], src_addr[1], src_addr[2], src_addr[3], sa->address_src->sadb_address_prefixlen);
 	printf("Dst Address:\n");
 	printf("\tProtocol:\t%s\n", print_ip_protocol(sa->address_dst->sadb_address_proto));
 	struct sockaddr_in* dst_sockaddr = (struct sockaddr_in*)((uint8_t*)sa->address_dst + sizeof(*sa->address_dst));
 	uint8_t* dst_addr = (uint8_t*)&(dst_sockaddr->sin_addr.s_addr);
 	printf("\tAddress:\t%u.%u.%u.%u/%d\n", dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3], sa->address_dst->sadb_address_prefixlen);
 	if(sa->address_proxy) {
 		printf("Proxy Address:\n");
 		printf("\tProtocol:\t%s\n", print_ip_protocol(sa->address_proxy->sadb_address_proto));
 		struct sockaddr_in* proxy_sockaddr = (struct sockaddr_in*)((uint8_t*)sa->address_proxy + sizeof(*sa->address_proxy));
 		uint8_t* proxy_addr = (uint8_t*)&(proxy_sockaddr->sin_addr.s_addr);
 		printf("\tAddress:\t%u.%u.%u.%u/%d\n", proxy_addr[0], proxy_addr[1], proxy_addr[2], proxy_addr[3], sa->address_proxy->sadb_address_prefixlen);
 	}
 	if(sa->key_auth) {
 		printf("Authentication Key:\n");
 		//TODO fix here
 		printf("\tKey:\t\t");
 		print_key((uint8_t*)sa->key_auth + sizeof(*sa->key_auth), sa->key_auth->sadb_key_bits / 8);
 	}
 	if(sa->key_encrypt) {
 		printf("Encryption Key:\n");
 		printf("\tKey:\t\t");
 		print_key((uint8_t*)sa->key_encrypt + sizeof(*sa->key_encrypt), sa->key_encrypt->sadb_key_bits / 8);
 	}
 	if(sa->x_sa2) {
 		printf("SA2:\n");
 		printf("\tMode:\t%s\n", print_mode(sa->x_sa2->sadb_x_sa2_mode));
 	}
 	printf("======================================\n");
}
