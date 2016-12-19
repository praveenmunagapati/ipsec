#include <net/ether.h>
#include <net/arp.h>
#include <net/icmp.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/checksum.h>
#include <thread.h>
#include <timer.h>
#include <shared.h>
#include <util/event.h>
#include <linux/ipsec.h>
#include <netinet/in.h>

#include <sapd.h>
#include "ipsec.h"
#include "esp.h"
#include "ah.h"
#include "socket.h"
#include "ike.h"
#include "mode.h"

static SAPD* sapd;
bool ipsec_ginit() {
	printf("==============================\n");
	printf("  ***  PacketNgin IPSec  ***  \n");
	printf("==============================\n\n");

	printf("Global Initializing IPSec...\n");
	printf("\tCreating SAPD...\n");
	sapd = sapd_create();
	if(!sapd) {
		printf("\tCreating SAPD is Fail\n");
		return false;
	}
	printf(".....................Success\n");

	printf("\tSetting Shared Memory...\n");
	shared_set(sapd);
	printf(".....................Success\n");

	printf("Global Initializing IPSec is Success\n\n");

	return true;
}

bool ipsec_init() {
	printf("Local Initializing IPSec...\n");
	printf("\tGetting Shared Memory...\n");
	void* shared_memory = shared_get();
	if(!shared_memory) {
		printf("\tGetting Shared Memory Fail\n");
		return false;
	}
	printf(".....................Success\n");
	printf("\tChecking SAPD...\n");
	if(!sapd_check(shared_memory)) {
		printf("\tChekcing SAPD Fail\n");
		return false;
	}
	sapd = shared_memory;
	printf(".....................Success\n");

	printf("\tInitializing Event...\n");
	event_init();
	printf("\tInitializing Event Success\n");
	printf("Local Initializing IPSec is Success\n\n");

	return true;
}

void ipsec_destroy() {
	//TODO Fix here
}

void ipsec_gdestroy() {
	//TODO Fix here
}

/*
   * TODO: fix this function
   * This function needs optimization.
  */
static bool route(Packet* packet) {
 	Ether* ether = (Ether*)(packet->buffer + packet->start);
        IP* ip = (IP*)ether->payload;
	NIC* default_nic = NULL;
	IPv4Interface* default_interface = NULL;
	uint32_t default_addr = 0;
 
	uint32_t count = nic_count();
	for(int i = 0; i < count; i++) {
		NIC* nic = nic_get(i);
		Map* interfaces = nic_config_get(nic, NIC_ADDR_IPv4);

		MapIterator iter;
		map_iterator_init(&iter, interfaces);
		while(map_iterator_has_next(&iter)) {
			MapEntry* entry = map_iterator_next(&iter);
			IPv4Interface* interface = entry->data;

			uint32_t addr = (uint32_t)(uint64_t)entry->key;

			if((endian32(ip->destination) & interface->netmask) == (addr & interface->netmask)) {
				ether->dmac = endian48(arp_get_mac(nic, endian32(ip->destination), addr));
				ether->smac = endian48(nic->mac);
				nic_output(nic, packet);

				return true;
			}

			if(interface->_default == true) {
				default_nic = nic;
				default_interface= interface;
				default_addr = addr;
			}
		}
	}

	if(default_nic) {
		ether->dmac = endian48(arp_get_mac(default_nic, default_interface->gateway, default_addr));
		ether->smac = endian48(default_nic->mac);
		nic_output(default_nic, packet);

		return true;
	}
 
	return false;
}

static bool ipsec_decrypt(SA* sa, Packet* packet) { 
	Ether* ether = (Ether*)(packet->buffer + packet->start);
        IP* ip = (IP*)ether->payload;
	ESP* esp = (ESP*)ip->body;
	// 2. Seq# Validation

	uint16_t len = endian16(ip->length) - ip->ihl * 4;
	if(sa->sa->sadb_sa_auth != SADB_EALG_NONE) {
		//TODO fix here: check protocol
		uint16_t auth_len = len - AUTH_DATA_LEN;
		if(!auth_check(sa->sa->sadb_sa_auth, ip->body + auth_len, ip->body, auth_len, (uint8_t*)sa->key_auth + sizeof(*sa->key_auth), sa->key_auth->sadb_key_bits / 8)) {
			return false;
		}
	}

	crypto_decrypt(sa->sa->sadb_sa_encrypt, esp->payload, len, (uint8_t*)sa->key_encrypt + sizeof(*sa->key_encrypt), sa->key_encrypt->sadb_key_bits / 8); 
	
	return true;
}


//Check auth
static bool ipsec_proof(SA* sa, Packet* packet) {
	Ether* ether = (Ether*)(packet->buffer + packet->start);
        IP* ip = (IP*)ether->payload;
	AH* ah = (AH*)ip->body;

	uint8_t ecn = ip->ecn;
	uint8_t dscp = ip->dscp;
	uint16_t flags_offset = ip->flags_offset;
	uint8_t ttl = ip->ttl;
	uint8_t auth_data[AUTH_DATA_LEN];
	memcpy(auth_data, ah->auth_data, AUTH_DATA_LEN);

	ip->ecn = 0;
	ip->dscp = 0;
	ip->ttl = 0;
	ip->flags_offset = 0;
	ip->checksum = 0;
	memset(ah->auth_data, 0, AUTH_DATA_LEN);

	if(!auth_check(sa->sa->sadb_sa_auth, auth_data, (uint8_t*)ip, endian16(ip->length), (uint8_t*)sa->key_auth + sizeof(*sa->key_auth), sa->key_auth->sadb_key_bits / 8)) {
		return false;
	}

	ip->ecn = ecn;
	ip->dscp = dscp;
	ip->flags_offset = flags_offset;
	ip->ttl = ttl;
// 
// 	if(ah->next_hdr == IP_PROTOCOL_IP && sa->address_proxy) {
// 		//Tunnel mode
// 		return tunnel_unset(packet, (ah->len + 2) * 4, 0);
// 	} else {
// 		//Transport mode
// 		ip->protocol = ah->next_hdr;
// 
// 		if(!transport_unset(packet, (ah->len + 2) * 4, 0))
// 			return false;
// 
// 		ether = (Ether*)(packet->buffer + packet->start);
// 		ip = (IP*)ether->payload;
// 		ip->checksum = endian16(checksum(ip, ip->ihl * 4));
// 	}

	return true;
}

static bool ipsec_auth(SA* sa, Packet* packet) {
	Ether* ether = NULL;
        IP* ip = NULL;
	AH* ah = NULL;

	uint16_t auth_len = 0;
	if(sa->address_proxy) {
		if(!tunnel_set(packet, 12 + auth_len, 0))
			return false;

		ether = (Ether*)(packet->buffer + packet->start);
		ip = (IP*)ether->payload;
		ah = (AH*)ip->body;

		//ip->length = endian16(endian16(ip->length) + IP_LEN + AH_HEADER_LEN + ICV_LEN);
		ah->next_hdr = IP_PROTOCOL_IP;
	} else {
		//TODO fix here auth_len
		if(!transport_set(packet, 12 + auth_len, 0))
			return false;

		ether = (Ether*)(packet->buffer + packet->start);
		ip = (IP*)ether->payload;
		ah = (AH*)ip->body;

		//ip->length = endian16(endian16(ip->length) + AH_HEADER_LEN + ICV_LEN);
		ah->next_hdr = ip->protocol;
	}

	ah->len = ((12 + auth_len) / 4) - 2;
	ah->spi = sa->sa->sadb_sa_spi;
	//TODO fix here
// 	ah->seq_num = endian32(++sa->window->seq_counter);

	uint8_t ecn = ip->ecn;
	uint8_t dscp = ip->dscp;
	uint8_t ttl = ip->ttl;
	uint16_t flags_offset = ip->flags_offset;

	ip->ecn = 0;
	ip->dscp = 0;
	ip->ttl = 0;
	ip->protocol = IP_PROTOCOL_AH;
	ip->flags_offset = 0;
	ip->checksum = 0;
	memset(ah->auth_data, 0, ICV_LEN);

	auth_request(sa->sa->sadb_sa_auth, ah->auth_data, (uint8_t*)ip, endian16(ip->length), (uint8_t*)sa->key_auth + sizeof(*sa->key_auth), sa->key_auth->sadb_key_bits / 8);

	ip->ecn = ecn;
	ip->dscp = dscp;
	if(sa->address_proxy) {
		ip->ttl = IP_TTL;
	} else {
		ip->ttl = ttl - 1;
	}
	ip->flags_offset = flags_offset;

	ip->checksum = endian16(checksum(ip, ip->ihl * 4));

	return true;
}

static bool inbound_process(Packet* packet) {
	Ether* ether = (Ether*)(packet->buffer + packet->start);
        IP* ip = (IP*)ether->payload;

	/*
	   * TODO: Fix here
	   * First version don't support multi encryption and authentication.
	 */
	SA* sa = NULL;
	if((ip->protocol == IP_PROTOCOL_ESP) || (ip->protocol == IP_PROTOCOL_AH)) {
		uint8_t head_len = 0;
		uint8_t tail_len = 0;
		switch(ip->protocol) {
			case IP_PROTOCOL_ESP:
				;
				ESP* esp = (ESP*)ip->body;
				sa = sapd_get_sa(sapd, endian32(esp->spi), endian32(ip->destination), ip->protocol);
				if(!sa) {
					return false;
				}
				if(!ipsec_decrypt(sa, packet)) {
					return false;
				}

				ESP_T* esp_trailer = (ESP_T*)(ip->body + endian16(ip->length) - (ip->ihl * 4) - ESP_TRAILER_LEN);
				head_len = ESP_HEADER_LEN;
				tail_len = esp_trailer->pad_len + ESP_TRAILER_LEN;
				break;

			case IP_PROTOCOL_AH:
				;
				AH* ah = (AH*)ip->body;
				sa = sapd_get_sa(sapd, endian32(ah->spi), endian32(ip->destination), ip->protocol);
				if(!sa) {
					return false;
				}
				if(!ipsec_proof(sa, packet)) {
					return false;
				}
				head_len = (ah->len + 2) * 4;
				tail_len = 0;
				break;
		}

		switch(sa->x_sa2->sadb_x_sa2_mode) {
			case IPSEC_MODE_TUNNEL:
				//TODO length check
				//TODO add get iv len
				if(!transport_unset(packet, head_len + ip->ihl * 4, tail_len))
					return false;

				break;
			case IPSEC_MODE_TRANSPORT:
				//TODO length check
				ip->protocol = esp_trailer->next_hdr;
				ip->ttl--;
				//TODO add get iv len
				if(!transport_unset(packet, head_len, tail_len))
					return false;

				ip->checksum = 0;
				ip->checksum = endian16(checksum(ip, ip->ihl * 4));

				break;
			default:
				return false;
		}
	}
	ether = (Ether*)(packet->buffer + packet->start);
	ip = (IP*)ether->payload;

	// 6. SPD Lookup 
	uint32_t src_address = endian32(ip->source);
	uint32_t dst_address = endian32(ip->destination);
	SP* sp = sapd_get_sp(sapd, IPSEC_POLICY_IPSEC, src_address, dst_address);
	if(!sp) {
		return false;
	}

	// TODO: 7. Verification
// 	if(!sp_verify_sa(sp, sa_list, ip)) {
// 		return false;
// 	}

	return true;
}

static bool outbound_process(SP* sp, Packet* packet) {
	Ether* ether = (Ether*)(packet->buffer + packet->start);
        IP* ip = (IP*)ether->payload;
	SA* sa = NULL;

	bool haed_set(uint16_t head_len) {
		return false;
	}

	bool tail_set(uint16_t tail_len) {
		return false;
	}

	bool ipsec_encrypt() {
		//TODO fix here
		ESP* esp = (ESP*)ip->body;
		uint32_t length = endian16(ip->length) - (ip->ihl * 4) - ESP_HEADER_LEN;
		crypto_encrypt(sa->sa->sadb_sa_encrypt, esp->payload, length, (uint8_t*)sa->key_encrypt + sizeof(*sa->key_encrypt), sa->key_encrypt->sadb_key_bits / 8);
		esp->spi = sa->sa->sadb_sa_spi;

		if(sa->sa->sadb_sa_auth != SADB_AALG_NONE) {
			//TODO Tail Length add AUTH_DATA_LEN
			uint16_t len = ip->length - (ip->ihl * 4);
			auth_request(sa->sa->sadb_sa_auth, ip->body + len, ip->body, len, (uint8_t*)sa->key_auth + sizeof(*sa->key_auth), sa->key_auth->sadb_key_bits / 8);
		}

		ip->protocol = IP_PROTOCOL_ESP;
		// 5. Seq# Validation
		//TODO set window
		// 	esp->seq_num = endian32(window_get_seq_counter(sa->window));
		return true;
	}

	bool transport_process(struct sadb_x_ipsecrequest* ipsecrequest) {
		sa = sp_get_sa_cache(sp, ip);
		if(!sa) {
			sa = sapd_get_sa(sapd, sa->sa->sadb_sa_spi, endian32(ip->source), endian32(ip->destination));
		}

		if(!sa)
			return false;

		switch(ipsecrequest->sadb_x_ipsecrequest_proto) {
			case IP_PROTOCOL_ESP:
				;
				//TODO fix: iv_len
				uint16_t iv_len = 0;
				uint16_t padding_len = (endian16(ip->length) - (ip->ihl * 4) + ESP_TRAILER_LEN) % iv_len;
				if(padding_len != 0)
					padding_len = iv_len - padding_len;
				if(!tail_set(padding_len + ESP_TRAILER_LEN)) {
					return false;
				}

				ESP_T* esp_trailer = (ESP_T*)(ip->body + endian16(ip->length) - (ip->ihl * 4) - ESP_TRAILER_LEN);
				esp_trailer->pad_len = padding_len;
				esp_trailer->next_hdr = ip->protocol;

				if(!head_set(ESP_HEADER_LEN)) {
					return false;
				}

				if(!ipsec_encrypt()) {
					return false;
				}
				break;
			case IP_PROTOCOL_AH:
				if(!transport_set(AH_HEADER_LEN)) {
					return false;
				}
				if(!ipsec_auth()) {
					return false;
				}
				break;
			default:
				return false;
		}

		ip->ttl--;
		ip->checksum = 0;
		ip->checksum = endian16(checksum(ip, ip->ihl * 4));
		return true;
	}

	bool tunnel_process(struct sadb_x_ipsecrequest* ipsecrequest) {
		SA* sa = sp_get_sa_cache(sp, ip);
		if(!sa)
			return false;

		struct sockaddr_in* sockaddr = (struct sockaddr_in*)((uint8_t*)ipsecrequest + sizeof(*ipsecrequest));
		uint32_t t_src_addr = sockaddr->sin_addr.s_addr;
		sockaddr++;
		uint32_t t_dst_addr = sockaddr->sin_addr.s_addr;
		if(!sa) {
			sa = sapd_get_sa(sapd, sa->sa->sadb_sa_spi, t_src_addr, t_dst_addr);
		}
		if(!sa)
			return false;

		switch(ipsecrequest->sadb_x_ipsecrequest_proto) {
			case IP_PROTOCOL_ESP:
				;
				//TODO fix: iv_len
				uint16_t iv_len = 0;
				uint16_t padding_len = (endian16(ip->length) - (ip->ihl * 4) + ESP_TRAILER_LEN) % iv_len;
				if(padding_len != 0)
					padding_len = iv_len - padding_len;
				if(!tail_set(padding_len + ESP_TRAILER_LEN)) {
					return false;
				}

				ESP_T* esp_trailer = (ESP_T*)(ip->body + endian16(ip->length) - (ip->ihl * 4) - ESP_TRAILER_LEN);
				esp_trailer->pad_len = padding_len;
				esp_trailer->next_hdr = IP_PROTOCOL_IP;

				if(!head_set(ESP_HEADER_LEN + IP_HEADER_LEN)) {
					return false;
				}

				break;
			case IP_PROTOCOL_AH:
				break;
			default:
				return false;
		}

		//TODO fix here
// 		uint16_t iv_len = iv_get_len(sa->);
// 		uint16_t padding_len = (endian16(ip->length) + ESP_TRAILER_LEN) % iv_len;
// 		if(padding_len != 0)
// 			padding_len = iv_len - padding_len;
// 		//TODO fix: iv_len
// 		if(!transport_set(packet, header_len, tail_len)) {
// 			return false;
// 		}

		//TODO tunnel set
		ether = (Ether*)(packet->buffer + packet->start);
		ip = (IP*)ether->payload;

		ip->ttl = IP_TTL;
		ip->source = endian32(t_src_addr);
		ip->destination = endian32(t_dst_addr);
		ip->checksum = 0;
		ip->checksum = endian16(checksum(ip, ip->ihl * 4));

		return true;
	}

	int len = sp->policy->sadb_x_policy_len * 8 - sizeof(*sp->policy);
	struct sadb_x_ipsecrequest* ipsecrequest = (struct sadb_x_ipsecrequest*)((uint8_t*)sp->policy + sizeof(struct sadb_x_ipsecrequest));
	while(len) {
		switch(ipsecrequest->sadb_x_ipsecrequest_mode) {
			case IPSEC_MODE_TRANSPORT:
				if(!transport_process(ipsecrequest))
					return false;
				break;
			case IPSEC_MODE_TUNNEL:
				if(!tunnel_process(ipsecrequest))
					return false;
				break;
			default:
				return false;
		}

		len -= ipsecrequest->sadb_x_ipsecrequest_len;
	}

	return true;
}


bool ipsec_process(Packet* packet) {
	Ether* ether = (Ether*)(packet->buffer + packet->start);
	if(endian16(ether->type) == ETHER_TYPE_IPv4) {
		IP* ip = (IP*)ether->payload;
		if(endian16(ip->length) != (packet->end - packet->start - ETHER_LEN)) {
			printf("Wrong IP Packet\n");
			printf("IP Length %d\n", endian16(ip->length));
			printf("Packet Length %d\n", packet->end - packet->start);
			return false;
		}

		uint32_t src_address = endian32(ip->source);
		uint32_t dst_address = endian32(ip->destination);
		SP* sp = sapd_get_sp(sapd, IPSEC_POLICY_IPSEC, src_address, dst_address);
			
		if(sp) {
			switch(sp->policy->sadb_x_policy_dir) {
				case IPSEC_DIR_OUTBOUND:
					if(!outbound_process(sp, packet)) { 
						nic_free(packet);
						return true;
					}
				default:
					nic_free(packet);
					return true;
			}
		} else {
			if(!inbound_process(packet)) {
				nic_free(packet);
				return true;
			}
		}

		if(!route(packet))
			nic_free(packet);

		return true;
	}

	return false;
}
