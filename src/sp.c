#include <stdint.h>
#include <stdbool.h>
#include <malloc.h>
#define DONT_MAKE_WRAPPER
#include <_malloc.h>
#undef DONT_MAKE_WRAPPER
#include <string.h>
#include <util/map.h>
#include <net/ip.h>
#include <linux/ipsec.h>
#include <netinet/in.h>

#include "sp.h"
#include "sa.h"

extern void* __gmalloc_pool;
SP* sp_alloc(int data_size) {
	SP* sp = (SP*)__malloc(sizeof(SP) + data_size, __gmalloc_pool);
	if(!sp) {
		printf("Can'nt allocate SP\n");
		return NULL;
	}
	memset(sp, 0, sizeof(SP) + data_size);
	return sp;
}

bool sp_free(SP* sp) {
	__free(sp, __gmalloc_pool);
	return true;
}

void sp_dump(SP* sp) {
	void ipsecrequest_dump(struct sadb_x_ipsecrequest* ipsecrequest) {
		char* print_proto(uint16_t proto) {
			switch(proto) {
				case IP_PROTOCOL_ESP:
					return "ESP";
				case IP_PROTOCOL_AH:
					return "AH";
				default:
					return "INVALID";
			}
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

		printf("\tIPSec Request\n");
		printf("\t\t\tProtocol: \t%s\n", print_proto(ipsecrequest->sadb_x_ipsecrequest_proto));
		printf("\t\t\tMode:\t\t%s\n", print_mode(ipsecrequest->sadb_x_ipsecrequest_mode));
		if(ipsecrequest->sadb_x_ipsecrequest_mode == IPSEC_MODE_TUNNEL) {
			struct sockaddr_in* sockaddr = (struct sockaddr_in*)((uint8_t*)ipsecrequest + sizeof(*ipsecrequest));
			uint8_t* addr = (uint8_t*)&(sockaddr->sin_addr.s_addr);
			printf("\t\t\tSrc Address:\t%u.%u.%u.%u\n", addr[0], addr[1], addr[2], addr[3]);
			sockaddr++;
			addr = (uint8_t*)&(sockaddr->sin_addr.s_addr);
			printf("\t\t\tDst Address:\t%u.%u.%u.%u\n", addr[0], addr[1], addr[2], addr[3]);
		}
		printf("\t\t\tID:\t%d\n", ipsecrequest->sadb_x_ipsecrequest_reqid);
	}

	char* print_sadb_type(uint16_t type) {
		switch(type) {
			case IPSEC_POLICY_DISCARD:
				return "DISCARD";
			case IPSEC_POLICY_NONE:
				return "NONE";
			case IPSEC_POLICY_IPSEC:
				return "IPSEC";
			case IPSEC_POLICY_ENTRUST:
				return "ENTRUST";
			case IPSEC_POLICY_BYPASS:
				return "BYPASS";
			default:
				return "INVALID";
		}
	}

	char* print_sadb_direction(uint8_t direction) {
		switch(direction) {
			case IPSEC_DIR_ANY:
				return "ANY";
			case IPSEC_DIR_INBOUND:
				return "INBOUND";
			case IPSEC_DIR_OUTBOUND:
				return "OUTBOUND";
			case IPSEC_DIR_FWD:
				return "FWD";
			default:
				return "INVALID";
		}
	}

	char* print_ip_protocol(uint8_t protocol) {
		switch(protocol) {
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
			case 255:
				return "ANY";
			default:
				return "INVALID";
		}
	}

	printf("======================================\n");
	printf("Policy:\n");
	printf("\tID:\t\t%u\n", sp->policy->sadb_x_policy_id);
	printf("\tType:\t\t%s\n", print_sadb_type(sp->policy->sadb_x_policy_type));
	printf("\tDirection:\t%s\n", print_sadb_direction(sp->policy->sadb_x_policy_dir));
	printf("\tPriority:\t%u\n", sp->policy->sadb_x_policy_priority);
	int len = sp->policy->sadb_x_policy_len * 8 - sizeof(*sp->policy);
	struct sadb_x_ipsecrequest* ipsecrequest = (struct sadb_x_ipsecrequest*)((uint8_t*)sp->policy + sizeof(struct sadb_x_ipsecrequest));
	while(len) {
		ipsecrequest_dump(ipsecrequest);
		len -= ipsecrequest->sadb_x_ipsecrequest_len;
		ipsecrequest = (struct sadb_x_ipsecrequest*)((uint8_t*)ipsecrequest + ipsecrequest->sadb_x_ipsecrequest_len * 8);
	}
	printf("Src Address:\n");
	printf("\tProtocol:\t%s\n", print_ip_protocol(sp->address_src->sadb_address_proto));
	struct sockaddr_in* src_sockaddr = (struct sockaddr_in*)((uint8_t*)sp->address_src + sizeof(*sp->address_src));
	uint8_t* src_addr = (uint8_t*)&(src_sockaddr->sin_addr.s_addr);
	printf("\tAddress:\t%u.%u.%u.%u/%d\n", src_addr[0], src_addr[1], src_addr[2], src_addr[3], sp->address_src->sadb_address_prefixlen);
	printf("Dst Address:\n");
	printf("\tProtocol:\t%s\n", print_ip_protocol(sp->address_dst->sadb_address_proto));
	struct sockaddr_in* dst_sockaddr = (struct sockaddr_in*)((uint8_t*)sp->address_dst + sizeof(*sp->address_dst));
	uint8_t* dst_addr = (uint8_t*)&(dst_sockaddr->sin_addr.s_addr);
	printf("\tAddress:\t%u.%u.%u.%u/%d\n", dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3], sp->address_dst->sadb_address_prefixlen);

	printf("======================================\n");
}

SA* sp_get_sa_cache(SP* sp, IP* ip) {
	return NULL;
}
