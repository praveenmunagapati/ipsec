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

static void ipsecrequest_dump(struct sadb_x_ipsecrequest* ipsecrequest) {
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

void sp_dump(SP* sp) {
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
	}
	printf("Src Address:\n");
	printf("\tProtocol:\t%s\n", print_ip_protocol(sp->address_src->sadb_address_proto));
	struct sockaddr_in* src_sockaddr = (struct sockaddr_in*)((uint8_t*)sp->address_src + sizeof(*sp->address_src));
	uint8_t* src_addr = (uint8_t*)&(src_sockaddr->sin_addr.s_addr);
	printf("\tAddress:\t%u.%u.%u.%u\n", src_addr[0], src_addr[1], src_addr[2], src_addr[3]);
	printf("Dst Address:\n");
	printf("\tProtocol:\t%s\n", print_ip_protocol(sp->address_dst->sadb_address_proto));
	struct sockaddr_in* dst_sockaddr = (struct sockaddr_in*)((uint8_t*)sp->address_dst + sizeof(*sp->address_dst));
	uint8_t* dst_addr = (uint8_t*)&(dst_sockaddr->sin_addr.s_addr);
	printf("\tAddress:\t%u.%u.%u.%u\n", dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]);

	printf("======================================\n");
}

SA* sp_get_sa_cache(SP* sp, IP* ip) {
	return NULL;
}
// bool sp_add_content(SP* sp, Content* content, int priority) {
// 	return list_add_at(sp->contents, priority, content);
// }
// 
// Content* sp_get_content(SP* sp, int index) {
// 	Content* content = list_get(sp->contents, index);
// 
// 	return content;
// }
// 
// bool sp_remove_content(SP* sp, int index) {
// 	Content* content = list_remove(sp->contents, index);
// 
// 	if(content) {
// 		content_free(content);
// 		return true;
// 	} else
// 		return false;
// }
// 
// bool sp_add_sa(SP* sp, SA* sa) {
// 	return list_add(sp->sa_list, sa);
// }
// 
// bool sp_remove_sa(SP* sp, SA* sa) {
// 	return list_remove_data(sp->sa_list, sa);
// }
// 
// //TODO
// SA* sp_get_sa(SP* sp, IP* ip) {
// 	if(!sp->sa_list)
// 		return NULL;
// 
// 	ListIterator iter;
// 	list_iterator_init(&iter, sp->sa_list);
// 	while(list_iterator_has_next(&iter)) {
// 		SA* sa = list_iterator_next(&iter);
// 		uint8_t protocol;
// 		if(sp->is_protocol_sa_share) {
// 			protocol = sp->protocol;
// 		} else {
// 			protocol = ip->protocol;
// 		}
// 		if(protocol != sa->protocol)
// 			continue;
// 
// 		if(sp->is_src_ip_sa_share) {
// 			if(sp->src_mask != sa->src_mask) {
// 				continue;
// 			}
// 
// 			uint32_t src_ip = sp->src_ip;
// 			if(!src_ip && ((src_ip & sp->src_mask) != (sa->src_ip & (sp->src_mask))))
// 				continue;
// 		} else {
// 			if(sa->src_mask != 0xffffffff)
// 				continue;
// 
// 			uint32_t src_ip = endian32(ip->source);
// 			if(src_ip != sa->src_ip)
// 				continue;
// 		}
// 
// 		if(sp->is_dest_ip_sa_share) {
// 			if(sp->dest_mask != sa->dest_mask)
// 				continue;
// 
// 			uint32_t dest_ip = sp->dest_ip;
// 			if(!dest_ip && ((dest_ip & sp->dest_mask) != (sa->dest_ip & (sp->dest_mask))))
// 				continue;
// 		} else {
// 			if(sa->dest_mask != 0xffffffff)
// 				continue;
// 
// 			uint32_t dest_ip = endian32(ip->destination);
// 			if(dest_ip != sa->dest_ip)
// 				continue;
// 		}
// 
// 		switch(ip->protocol) {
// 			case IP_PROTOCOL_TCP:
// 				;
// 				TCP* tcp = (TCP*)ip->body;
// 				if(sp->is_src_port_sa_share) {
// 					uint16_t src_port = sp->src_port;
// 					if(src_port != sa->src_port)
// 						continue;
// 				} else {
// 					uint16_t src_port = endian16(tcp->source);
// 					if(src_port != sa->src_port)
// 						continue;
// 				}
// 
// 				if(sp->is_dest_port_sa_share) {
// 					uint16_t dest_port = sp->dest_port;
// 					if(dest_port != sa->dest_port)
// 						continue;
// 				} else {
// 					uint16_t dest_port = endian16(tcp->destination);
// 					if(dest_port != sa->dest_port)
// 						continue;
// 				}
// 
// 				return sa;
// 			case IP_PROTOCOL_UDP:
// 				;
// 				UDP* udp = (UDP*)ip->body;
// 				if(sp->is_src_port_sa_share) {
// 					uint16_t src_port = sp->src_port;
// 					if(src_port != sa->src_port)
// 						continue;
// 				} else {
// 					uint16_t src_port = endian16(udp->source);
// 					if(src_port != sa->src_port)
// 						continue;
// 				}
// 
// 				if(sp->is_dest_port_sa_share) {
// 					uint16_t dest_port = sp->dest_port;
// 					if(dest_port != sa->dest_port)
// 						continue;
// 				} else {
// 					uint16_t dest_port = endian16(udp->destination);
// 					if(dest_port != sa->dest_port)
// 						continue;
// 				}
// 
// 				return sa;
// 			default:
// 				return sa;
// 		}
// 
// 	}
// 
// 	return NULL;
// }
// 
// //return SA or SA Bundle
// SA* sp_find_sa(SP* sp, IP* ip) {
// 	SA* first_sa = NULL;
// 	SA* pre_sa = NULL;
// 
// 	SAD* sad = sad_get(sp->nic);
// 
// 	ListIterator iter;
// 	list_iterator_init(&iter, sp->contents);
// 	while(list_iterator_has_next(&iter)) {
// 		SA* next_sa = NULL;
// 		Content* content = list_iterator_next(&iter);
// 
// 		MapIterator sad_iter;
// 		map_iterator_init(&sad_iter, sad->database);
// 		while(map_iterator_has_next(&sad_iter)) {
// 			MapEntry* entry = map_iterator_next(&sad_iter);
// 			List* dest_list = entry->data;
// 
// 			ListIterator list_iter;
// 			list_iterator_init(&list_iter, dest_list);
// 			while(list_iterator_has_next(&list_iter)) {
// 				SA* sa = list_iterator_next(&list_iter);
// 				if(content->ipsec_protocol != sa->ipsec_protocol)
// 					continue;
// 
// 				//mode check
// 				if(content->ipsec_mode != sa->ipsec_mode)
// 					continue;
// 
// 				//algorithm check
// 				switch(content->ipsec_mode) {
// 					case IPSEC_MODE_TRANSPORT:
// 						if(content->ipsec_protocol == IP_PROTOCOL_ESP) {
// 							if(((Content_ESP_Transport*)content)->crypto_algorithm != ((SA_ESP*)sa)->crypto_algorithm)
// 								continue;
// 
// 							if(((Content_ESP_Transport*)content)->auth_algorithm != ((SA_ESP*)sa)->auth_algorithm)
// 								continue;
// 						} else {
// 							if(((Content_AH_Transport*)content)->auth_algorithm != ((SA_AH*)sa)->auth_algorithm)
// 								continue;
// 						}
// 
// 						break;
// 					case IPSEC_MODE_TUNNEL:
// 						;
// 						uint32_t t_src_ip;
// 						uint32_t t_dest_ip;
// 						if(content->ipsec_protocol == IP_PROTOCOL_ESP) {
// 							if(((Content_ESP_Tunnel*)content)->crypto_algorithm != ((SA_ESP*)sa)->crypto_algorithm) {
// 								continue;
// 							}
// 
// 							if(((Content_ESP_Tunnel*)content)->auth_algorithm != ((SA_ESP*)sa)->auth_algorithm)
// 								continue;
// 							
// 							t_src_ip = ((Content_ESP_Tunnel*)content)->t_src_ip;
// 							t_dest_ip = ((Content_ESP_Tunnel*)content)->t_dest_ip;
// 						} else {
// 							if(((Content_AH_Tunnel*)content)->auth_algorithm != ((SA_AH*)sa)->auth_algorithm)
// 								continue;
// 
// 							t_src_ip = ((Content_AH_Tunnel*)content)->t_src_ip;
// 							t_dest_ip = ((Content_AH_Tunnel*)content)->t_dest_ip;
// 						}
// 						
// 						//ip check
// 						if(sa->t_src_ip != t_src_ip)
// 							continue;
// 
// 						if(sa->t_dest_ip != t_dest_ip)
// 							continue;
// 						break;
// 				}
// 
// 				//address check
// 				if(!first_sa) {
// 					//TODO add protocol
// 					if(sp->is_src_ip_sa_share) {
// 						if(sp->src_ip != sa->src_ip || sp->src_mask != sa->src_mask)
// 							continue;
// 					} else {
// 						uint32_t src_ip = endian32(ip->source);
// 						if(src_ip != sa->src_ip || sa->src_mask != 0xffffffff)
// 							continue;
// 					}
// 
// 					if(sp->is_dest_ip_sa_share) {
// 						if(sp->dest_ip != sa->dest_ip || sp->dest_mask != sa->dest_mask)
// 							continue;
// 					} else {
// 						uint32_t dest_ip = endian32(ip->source);
// 						if(dest_ip != sa->dest_ip || sa->dest_mask != 0xffffffff)
// 							continue;
// 					}
// 
// 					//TODO add port
// 				} else {
// 					if(pre_sa->src_ip != sa->src_ip || pre_sa->src_mask != sa->src_mask)
// 						continue;
// 
// 					if(pre_sa->dest_ip != sa->dest_ip || pre_sa->dest_mask != sa->dest_mask)
// 						continue;
// 				}
// 				
// 				next_sa = sa;
// 				goto next;
// 			}
// 		}
// 
// next:
// 		if(!next_sa) {
// 			printf("Can'nt found SA\n");
// 			return NULL;
// 		}
// 		if(!first_sa) {
// 			first_sa = next_sa;
// 			pre_sa = next_sa;
// 		} else {
// 			pre_sa->next = next_sa;
// 			pre_sa = next_sa;
// 		}
// 	}
// 	sp_add_sa(sp, first_sa);
// 
// 	return first_sa;
// }
// 
// bool sp_verify_sa(SP* sp, List* sa_list, IP* ip) {
// 	SA* pre_sa = NULL;
// 	ListIterator iter;
// 	list_iterator_init(&iter, sp->contents);
// 	while(list_iterator_has_next(&iter)) {
// 		SA* sa = list_remove_first(sa_list);
// 		if(!sa)
// 			return false;
// 
// 		Content* content = list_iterator_next(&iter);
// 		// verification SA
// 
// 		if(content->ipsec_protocol != sa->ipsec_protocol)
// 			return false;
// 
// 		//mode check
// 		if(content->ipsec_mode != sa->ipsec_mode)
// 			return false;
// 		
// 		switch(content->ipsec_mode) {
// 			case IPSEC_MODE_TRANSPORT:
// 				if(content->ipsec_protocol == IP_PROTOCOL_ESP) {
// 					if(((Content_ESP_Transport*)content)->crypto_algorithm != ((SA_ESP*)sa)->crypto_algorithm)
// 						return false;
// 
// 					if(((Content_ESP_Transport*)content)->auth_algorithm != ((SA_ESP*)sa)->auth_algorithm)
// 						return false;
// 				} else {
// 					if(((Content_AH_Transport*)content)->auth_algorithm != ((SA_AH*)sa)->auth_algorithm)
// 						return false;
// 				}
// 
// 				break;
// 			case IPSEC_MODE_TUNNEL:
// 				;
// 				uint32_t t_src_ip;
// 				uint32_t t_dest_ip;
// 				if(content->ipsec_protocol == IP_PROTOCOL_ESP) {
// 					if(((Content_ESP_Tunnel*)content)->crypto_algorithm != ((SA_ESP*)sa)->crypto_algorithm) {
// 						return false;
// 					}
// 
// 					if(((Content_ESP_Tunnel*)content)->auth_algorithm != ((SA_ESP*)sa)->auth_algorithm)
// 						return false;
// 					
// 					t_src_ip = ((Content_ESP_Tunnel*)content)->t_src_ip;
// 					t_dest_ip = ((Content_ESP_Tunnel*)content)->t_dest_ip;
// 				} else {
// 					if(((Content_AH_Tunnel*)content)->auth_algorithm != ((SA_AH*)sa)->auth_algorithm)
// 						return false;
// 
// 					t_src_ip = ((Content_AH_Tunnel*)content)->t_src_ip;
// 					t_dest_ip = ((Content_AH_Tunnel*)content)->t_dest_ip;
// 				}
// 				
// 				//ip check
// 				if(sa->t_src_ip != t_src_ip)
// 					return false;
// 
// 				if(sa->t_dest_ip != t_dest_ip)
// 					return false;
// 				break;
// 		}
// 
// 		//address check
// 		if(!pre_sa) {
// 			//TODO add protocol
// 			if(sp->is_src_ip_sa_share) {
// 				if(sp->src_ip != sa->src_ip || sp->src_mask != sa->src_mask)
// 					return false;
// 			} else {
// 				uint32_t src_ip = endian32(ip->source);
// 				if(src_ip != sa->src_ip || sa->src_mask != 0xffffffff)
// 					return false;
// 			}
// 
// 			if(sp->is_dest_ip_sa_share) {
// 				if(sp->dest_ip != sa->dest_ip || sp->dest_mask != sa->dest_mask)
// 					return false;
// 			} else {
// 				uint32_t dest_ip = endian32(ip->source);
// 				if(dest_ip != sa->dest_ip || sa->dest_mask != 0xffffffff)
// 					return false;
// 			}
// 
// 			//TODO add port
// 		} else {
// 			if(pre_sa->src_ip != sa->src_ip || pre_sa->src_mask != sa->src_mask)
// 				return false;
// 
// 			if(pre_sa->dest_ip != sa->dest_ip || pre_sa->dest_mask != sa->dest_mask)
// 				return false;
// 		}
// 
// 		pre_sa = sa;
// 	}
// 
// 	return true;
// }
