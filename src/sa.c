#include <malloc.h>
#define DONT_MAKE_WRAPPER
#include <_malloc.h>
#undef DONT_MAKE_WRAPPER
#include <string.h>
#include <net/ip.h>

#include "sa.h"
#include <byteswap.h>

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
	free(sa);
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
				return "SHA2 256HMAC";
			case SADB_X_AALG_SHA2_384HMAC:
				return "SHA2 384HMAC";
			case SADB_X_AALG_SHA2_512HMAC:
				return "SHA2 512HMAC";
			case SADB_X_AALG_RIPEMD160HMAC:
				return "RIPEMD 160HMAC";
			case SADB_X_AALG_AES_XCBC_MAC:
				return "AES XCBC MAC";
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
				return "DES CBC";
			case SADB_EALG_3DESCBC:
				return "3DES CBC";
			case SADB_X_EALG_CASTCBC:
				return "CAST CBC";
			case SADB_X_EALG_BLOWFISHCBC:
				return "BLOWFISH CBC";
			case SADB_EALG_NULL:
				return "NULL";
			case SADB_X_EALG_AESCBC:
				return "AES CBC";
			case SADB_X_EALG_AESCTR:
				return "AES CTR";
			case SADB_X_EALG_AES_CCM_ICV8:
				return "AES CCM ICV8";
			case SADB_X_EALG_AES_CCM_ICV12:
				return "AES CCM ICV12";
			case SADB_X_EALG_AES_CCM_ICV16:
				return "AES CCM ICV16";
			case SADB_X_EALG_AES_GCM_ICV8:
				return "AES GCM ICV8";
			case SADB_X_EALG_AES_GCM_ICV12:
				return "AES GCM ICV12";
			case SADB_X_EALG_AES_GCM_ICV16:
				return "AES GCM ICV16";
			case SADB_X_EALG_CAMELLIACBC:
				return "CAMELLIA CBC";
			case SADB_X_EALG_NULL_AES_GMAC:
				return "NULL AES GMAC";
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
	printf("\tSA Type:\t\t%s\n", print_sa_type(sa->sadb_msg->sadb_msg_satype));
	printf("\tSPI:\t\t0x%x\n", bswap_32(sa->sa->sadb_sa_spi));
	printf("\tAuth:\t\t%s\n", print_sadb_auth(sa->sa->sadb_sa_auth));
	printf("\tEncryption:\t%s\n", print_sadb_encrypt(sa->sa->sadb_sa_encrypt));
	printf("Src Address:\n");
	printf("\tProtocol:\t%s\n", print_ip_protocol(sa->address_src->sadb_address_proto));
	struct sockaddr_in* src_sockaddr = (struct sockaddr_in*)((uint8_t*)sa->address_src + sizeof(*sa->address_src));
	uint8_t* src_addr = (uint8_t*)&(src_sockaddr->sin_addr.s_addr);
	printf("\tAddress:\t%u.%u.%u.%u\n", src_addr[0], src_addr[1], src_addr[2], src_addr[3]);
	printf("Dst Address:\n");
	printf("\tProtocol:\t%s\n", print_ip_protocol(sa->address_dst->sadb_address_proto));
	struct sockaddr_in* dst_sockaddr = (struct sockaddr_in*)((uint8_t*)sa->address_dst + sizeof(*sa->address_dst));
	uint8_t* dst_addr = (uint8_t*)&(dst_sockaddr->sin_addr.s_addr);
	printf("\tAddress:\t%u.%u.%u.%u\n", dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]);
	if(sa->address_proxy) {
		printf("Proxy Address:\n");
		printf("\tProtocol:\t%s\n", print_ip_protocol(sa->address_proxy->sadb_address_proto));
		struct sockaddr_in* proxy_sockaddr = (struct sockaddr_in*)((uint8_t*)sa->address_proxy + sizeof(*sa->address_proxy));
		uint8_t* proxy_addr = (uint8_t*)&(proxy_sockaddr->sin_addr.s_addr);
		printf("\tAddress:\t%u.%u.%u.%u\n", proxy_addr[0], proxy_addr[1], proxy_addr[2], proxy_addr[3]);
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
// 
// SA* sa_alloc(NIC* nic, uint64_t* attrs) {
// 	bool has_key(uint64_t key) {
// 		int i = 0;
// 		while(attrs[i * 2] != NIC_NONE) {
// 			if(attrs[i * 2] == key)
// 				return true;
// 
// 			i++;
// 		}
// 
// 		return false;
// 	}
// 
// 	uint64_t get_value(uint64_t key) {
// 		int i = 0;
// 		while(attrs[i * 2] != NIC_NONE) {
// 			if(attrs[i * 2] == key)
// 				return attrs[i * 2 + 1];
// 
// 			i++;
// 		}
// 
// 		return (uint64_t)-1;
// 	}
// 
// 
// 	uint64_t value = get_value(SA_CRYPTO_ALGORITHM);
// 	if(value) {
// 		//case esp
// 		if(!has_key(SA_CRYPTO_KEY)) {
// 			return NULL;
// 		}
// 		sa->ipsec_protocol = IP_PROTOCOL_ESP;
// 	} else {
// 		if(!has_key(SA_AUTH_KEY)) {
// 			return NULL;
// 		}
// 		sa = __malloc(sizeof(SA_AH), nic->pool);
// 		if(!sa) {
// 			printf("Can't allocate SA\n");
// 			return NULL;
// 		}
// 		memset(sa, 0, sizeof(SA_AH));
// 		sa->nic = nic;
// 		sa->ipsec_protocol = IP_PROTOCOL_AH;
// 	}
// 
// 	sa->src_mask = 0xffffffff;
// 	sa->dest_mask = 0xffffffff;
// 
// 	for(int i = 0; attrs[i * 2] != SA_NONE; i++) {
// 		switch(attrs[i * 2]) {
// 			case SA_IPSEC_MODE:
// 				sa->ipsec_mode = (uint8_t)attrs[i * 2 + 1];
// 				break;
// 			case SA_TUNNEL_SOURCE_IP:
// 				sa->t_src_ip = (uint32_t)attrs[i * 2 + 1];
// 				break;
// 			case SA_TUNNEL_DESTINATION_IP:
// 				sa->t_dest_ip = (uint32_t)attrs[i * 2 + 1];
// 				break;
// 			case SA_SPI:
// 				sa->spi = (uint32_t)attrs[i * 2 + 1];
// 				break;
// 			case SA_PROTOCOL:
// 				sa->protocol = (uint8_t)attrs[i * 2 + 1];
// 				break;
// 			case SA_SOURCE_IP:
// 				sa->src_ip = (uint32_t)attrs[i * 2 + 1];
// 				break;
// 			case SA_SOURCE_MASK:
// 				sa->src_mask = (uint32_t)attrs[i * 2 + 1];
// 				break;
// 			case SA_DESTINATION_IP:
// 				sa->dest_ip = (uint32_t)attrs[i * 2 + 1];
// 				break;
// 			case SA_DESTINATION_MASK:
// 				sa->dest_mask = (uint32_t)attrs[i * 2 + 1];
// 				break;
// 			case SA_SOURCE_PORT:
// 				sa->src_port = (uint16_t)attrs[i * 2 + 1];
// 				break;
// 			case SA_DESTINATION_PORT:
// 				sa->dest_port = (uint16_t)attrs[i * 2 + 1];
// 				break;
// 			case SA_CRYPTO_ALGORITHM:
// 				if(sa->ipsec_protocol == IP_PROTOCOL_ESP) {
// 					((SA_ESP*)sa)->crypto_algorithm = (uint8_t)attrs[i * 2 + 1];
// 				}
// 				break;
// 			case SA_CRYPTO_KEY:
// 				((SA_ESP*)sa)->crypto_key = (uint64_t*)attrs[i * 2 + 1];
// 
// 				uint16_t crypto_key_length = get_value(SA_CRYPTO_KEY_LENGTH);
// 				uint8_t algorithm = get_value(SA_CRYPTO_ALGORITHM);
// 				switch(algorithm) {
// 					case SADB_EALG_NONE:
// 						break;
// 					case SADB_EALG_DESCBC:
// 						;
// 						/*Des*/
// 						DES_cblock des_key;
// 						uint64_t key = *(uint64_t*)(((SA_ESP*)sa)->crypto_key);
// 						memcpy(des_key, &key, sizeof(DES_cblock));
// 						DES_set_odd_parity(&des_key);
// 
// 						DES_key_schedule* ks = __malloc(sizeof(DES_key_schedule), nic->pool);
// 						if(!ks) {
// 							printf("Can't allocate key\n");
// 							goto fail_key_alloc;
// 						}
// 						if(DES_set_key_checked(&des_key, ks)) {
// 							printf("Encrypt key is weak key\n");
// 							__free(ks, nic->pool);
// 							goto error_set_key;
// 						}
// 
// 						((SA_ESP*)sa)->encrypt_key = ks;
// 						((SA_ESP*)sa)->decrypt_key = ks;
// 						break;
// 					case SADB_EALG_3DESCBC:
// 						/*3Des*/
// 						;
// 						DES_cblock des_key_3[3];
// 						memcpy(des_key_3, ((SA_ESP*)sa)->crypto_key, sizeof(DES_cblock) * 3);
// 						for(int i = 0; i < 3; i++)
// 							DES_set_odd_parity(&des_key_3[i]);
// 
// 						DES_key_schedule* ks_3 = __malloc(sizeof(DES_key_schedule) * 3, nic->pool);
// 						if(!ks_3) {
// 							printf("Can't allocate key\n");
// 							goto fail_key_alloc;
// 						}
// 						if(DES_set_key_checked(&des_key_3[0], &ks_3[0]) || DES_set_key_checked(&des_key_3[1], &ks_3[1]) || DES_set_key_checked(&des_key_3[2], &ks_3[2])) {
// 							printf("Encrypt key is weak key\n");
// 							__free(ks_3, nic->pool);
// 							goto error_set_key;
// 						}
// 
// 						((SA_ESP*)sa)->encrypt_key = ks_3;
// 						((SA_ESP*)sa)->decrypt_key = ks_3;
// 						break;
// 					case SADB_X_EALG_CASTCBC:
// 						;
// 						/*Cast*/
// 						CAST_KEY* cast_key = __malloc(sizeof(CAST_KEY), nic->pool);
// 						if(!cast_key) {
// 							printf("Can't allocate key\n");
// 							goto fail_key_alloc;
// 						}
// 						CAST_set_key(cast_key, crypto_key_length, (const unsigned char*)((SA_ESP*)sa)->crypto_key);
// 						((SA_ESP*)sa)->encrypt_key = cast_key;
// 						((SA_ESP*)sa)->decrypt_key = cast_key;
// 						break;
// 					case SADB_X_EALG_BLOWFISHCBC:
// 						;
// 						/*BF*/
// 						BF_KEY* bf_key = __malloc(sizeof(BF_KEY), nic->pool);
// 						if(!bf_key) {
// 							printf("Can't allocate key\n");
// 							goto fail_key_alloc;
// 						}
// 						BF_set_key(bf_key, crypto_key_length, (const unsigned char*)((SA_ESP*)sa)->crypto_key);
// 						((SA_ESP*)sa)->encrypt_key = bf_key;
// 						((SA_ESP*)sa)->decrypt_key = bf_key;
// 						break;
// 					case SADB_EALG_NULL:
// 						break;
// 					case SADB_X_EALG_AESCBC:
// 						//TODO check rjindael == aescbc?
// 						;
// 						{
// 						AES_KEY* encrypt_key = __malloc(sizeof(AES_KEY), nic->pool);
// 						if(!encrypt_key) {
// 							printf("Can't allocate key\n");
// 							goto fail_key_alloc;
// 						}
// 						AES_KEY* decrypt_key = __malloc(sizeof(AES_KEY), nic->pool);
// 						if(!decrypt_key) {
// 							printf("Can't allocate key\n");
// 							__free(encrypt_key, nic->pool);
// 							goto fail_key_alloc;
// 						}
// 						if(AES_set_encrypt_key((const unsigned char*)((SA_ESP*)sa)->crypto_key, crypto_key_length * 8, encrypt_key)) {
// 							printf("Wrong key\n");
// 							__free(encrypt_key, nic->pool);
// 							__free(decrypt_key, nic->pool);
// 							goto fail_key_alloc;
// 						}
// 						if(AES_set_decrypt_key((const unsigned char*)((SA_ESP*)sa)->crypto_key, crypto_key_length * 8, decrypt_key)) {
// 							printf("Wrong key\n");
// 							__free(encrypt_key, nic->pool);
// 							__free(decrypt_key, nic->pool);
// 							goto fail_key_alloc;
// 						}
// 						((SA_ESP*)sa)->encrypt_key = encrypt_key;
// 						((SA_ESP*)sa)->decrypt_key = decrypt_key;
// 						}
// 						break;
// 					case SADB_X_EALG_AESCTR:
// 						;
// 						{
// 						/*AES*/
// 						AES_KEY* encrypt_key = __malloc(sizeof(AES_KEY), nic->pool);
// 						if(!encrypt_key) {
// 							printf("Can't allocate key\n");
// 							goto fail_key_alloc;
// 						}
// 						if(AES_set_encrypt_key((const unsigned char*)((SA_ESP*)sa)->crypto_key, (crypto_key_length - 4) * 8, encrypt_key)) {
// 							printf("Wrong key\n");
// 							__free(encrypt_key, nic->pool);
// 							//__free(decrypt_key, nic->pool);
// 							goto fail_key_alloc;
// 						}
// 
// 						((SA_ESP*)sa)->encrypt_key = encrypt_key;
// 						((SA_ESP*)sa)->decrypt_key = encrypt_key;
// 						}
// 						break;
// 					case SADB_X_EALG_AES_CCM_ICV8:
// 					case SADB_X_EALG_AES_CCM_ICV12:
// 					case SADB_X_EALG_AES_CCM_ICV16:
// 					case SADB_X_EALG_AES_GCM_ICV8:
// 					case SADB_X_EALG_AES_GCM_ICV12:
// 					case SADB_X_EALG_AES_GCM_ICV16:
// 						break;
// 					case SADB_X_EALG_CAMELLIACBC:
// 						;
// 						/*Camellia*/
// 						CAMELLIA_KEY* camellia_key = __malloc(sizeof(CAMELLIA_KEY), nic->pool);
// 						if(!camellia_key) {
// 							printf("Can't allocate key\n");
// 							__free(camellia_key, nic->pool);
// 							goto fail_key_alloc;
// 						}
// 						printf("crypto_key_length : %d\n", crypto_key_length);
// 						if(Camellia_set_key((const unsigned char*)((SA_ESP*)sa)->crypto_key, crypto_key_length * 8, camellia_key)) {
// 							printf("Wrong key\n");
// 							__free(camellia_key, nic->pool);
// 							goto fail_key_alloc;
// 						}
// 						((SA_ESP*)sa)->encrypt_key = camellia_key;
// 						((SA_ESP*)sa)->decrypt_key = camellia_key;
// 						break;
// 					case SADB_X_EALG_NULL_AES_GMAC:
// 					case SADB_X_EALG_SERPENTCBC:
// 					case SADB_X_EALG_TWOFISHCBC:
// 						break;
// 				}
// 				break;
// 			case SA_CRYPTO_KEY_LENGTH:
// 				((SA_ESP*)sa)->crypto_key_length = (uint16_t)attrs[i * 2 + 1];
// 				break;
// 			case SA_IV_SUPPORT:
// 				((SA_ESP*)sa)->iv = (bool)attrs[i * 2 + 1];
// 				break;
// 			case SA_AUTH_ALGORITHM:
// 				if(sa->ipsec_protocol == IP_PROTOCOL_AH) { 
// 						((SA_AH*)sa)->auth_algorithm = (uint8_t)attrs[i * 2 + 1];
// 				} else {
// 						if(!attrs[i * 2 + 1]) {
// 							break;
// 						}
// 						((SA_ESP*)sa)->auth_algorithm = (uint8_t)attrs[i * 2 + 1];
// 				}
// 				break;
// 			case SA_AUTH_KEY:
// 				if(sa->ipsec_protocol == IP_PROTOCOL_AH) {  
// 						((SA_AH*)sa)->auth_key = (uint64_t*)attrs[i * 2 + 1];
// 				} else {
// 						((SA_ESP*)sa)->auth_key = (uint64_t*)attrs[i * 2 + 1];
// 				}
// 				break;
// 			case SA_AUTH_KEY_LENGTH:
// 				if(sa->ipsec_protocol == IP_PROTOCOL_AH) {   
// 						((SA_AH*)sa)->auth_key_length = (uint32_t)attrs[i * 2 + 1];
// 				} else {
// 						((SA_ESP*)sa)->auth_key_length = (uint32_t)attrs[i * 2 + 1];
// 				}
// 				break;
// 			case SA_REPLY:
// 				if(attrs[i * 2 + 1]) {
// 					sa->window = (Window*)__malloc(sizeof(Window), nic->pool);
// 					if(!sa->window) {
// 						printf("Can't allocate window\n");
// 						goto sa_free;
// 					}
// 					memset(sa->window, 0x0, sizeof(Window));
// 				}
// 				break;
// 		}
// 	}
// 
// 	return sa;
// 
// fail_key_alloc:
// error_set_key:
// sa_free:
// 	if(sa->ipsec_protocol == IP_PROTOCOL_ESP) {
// 		if(((SA_ESP*)sa)->encrypt_key) {
// 			if(((SA_ESP*)sa)->encrypt_key == ((SA_ESP*)sa)->decrypt_key) {
// 				__free(((SA_ESP*)sa)->encrypt_key, nic->pool);
// 			} else {
// 				//AES key
// 				__free(((SA_ESP*)sa)->encrypt_key, nic->pool);
// 				__free(((SA_ESP*)sa)->decrypt_key, nic->pool);
// 			}
// 		}
// 	} else if(sa->ipsec_protocol == IP_PROTOCOL_AH) {
// 	}
// 	if(sa->window) {
// 		__free(sa->window, nic->pool);
// 	}
// 	__free(sa, nic->pool);
// 
// 	return NULL;
// }
// 
// bool sa_free(SA* sa) {
// 	if(sa->ipsec_protocol == IP_PROTOCOL_ESP) {
// 		if(((SA_ESP*)sa)->encrypt_key) {
// 			if(((SA_ESP*)sa)->encrypt_key == ((SA_ESP*)sa)->decrypt_key) {
// 				__free(((SA_ESP*)sa)->encrypt_key, sa->nic->pool);
// 			} else {
// 				//AES key
// 				__free(((SA_ESP*)sa)->encrypt_key, sa->nic->pool);
// 				__free(((SA_ESP*)sa)->decrypt_key, sa->nic->pool);
// 			}
// 		}
// 		if(((SA_ESP*)sa)->auth_key) {
// 			__free(((SA_ESP*)sa)->auth_key, sa->nic->pool);
// 		}
// 	} else if(sa->ipsec_protocol == IP_PROTOCOL_AH) {
// 		if(((SA_AH*)sa)->auth_key) {
// 			__free(((SA_AH*)sa)->auth_key, sa->nic->pool);
// 		}
// 	}
// 	__free(sa->window, sa->nic->pool);
// 	__free(sa, sa->nic->pool);
// 
// 	return true;
// }
