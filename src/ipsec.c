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
#include "route.h"

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

void ipsec_dump() {
	SAD* sad = sapd->sad;

	MapIterator iter;
	rwlock_rlock(&sad->rwlock);
	map_iterator_init(&iter, sad->database);
	while(map_iterator_has_next(&iter)) {
		MapEntry* entry = map_iterator_next(&iter);
		Map* _sad = entry->data;
		MapIterator _iter;
		map_iterator_init(&_iter, _sad);
		while(map_iterator_has_next(&_iter)) {
			MapEntry* _entry = map_iterator_next(&_iter);
			SA* sa = _entry->data;
			sa_dump(sa);
		}
	}
	rwlock_runlock(&sad->rwlock);
}

void ipsec_spddump() {
	SPD* spd = sapd->spd;

	ListIterator iter;
	rwlock_rlock(&spd->rwlock);
	list_iterator_init(&iter, spd->list);
	while(list_iterator_has_next(&iter)) {
		SP* sp = list_iterator_next(&iter);
		sp_dump(sp);
	}
	rwlock_runlock(&spd->rwlock);
}

void dump_packet(Packet* packet) {
	for(int i = packet->start; i < packet->end; i++) {
		for(int j = 16; i < packet->end && j < 16; j++, i++)
			printf("%02x", packet->buffer + i);
		printf("\n");
	}
}

static bool inbound_process(Packet* packet) {
	Ether* ether = (Ether*)(packet->buffer + packet->start);
        IP* ip = (IP*)ether->payload;

	bool transport_unset(uint16_t header_len) {
		memmove((uint8_t*)ether + header_len, ether, ETHER_LEN + (ip->ihl * 4));

		packet->start += header_len;
		ether = (Ether*)((uint8_t*)ether + header_len);
		ip = (IP*)((uint8_t*)ip + header_len);
		ip->length = endian16(endian16(ip->length) - header_len);

		return true;
	}

	bool tunnel_unset(uint16_t header_len) {
		packet->start += (header_len + (ip->ihl * 4));
		ether = (Ether*)(packet->buffer + packet->start);
		ether->dmac = endian48(0xffffffffffff);
		ether->smac = endian48(0xffffffffffff);
		ether->type = endian16(ETHER_TYPE_IPv4);
		ip = (IP*)ether->payload;
		
		return true;
	}

	bool tail_unset(uint16_t tail_len) {
		packet->end -= tail_len;
		ip->length = endian16(endian16(ip->length) - tail_len);
		return true;
	}

	bool ipsec_decrypt(SA* sa) { 
		ESP* esp = (ESP*)ip->body;

		uint16_t len = endian16(ip->length) - ip->ihl * 4;
		if(sa->sa->sadb_sa_auth != SADB_EALG_NONE) {
			uint16_t auth_len = len - auth_auth_data_len(sa->sa->sadb_sa_auth);
			if(!auth_check(sa->sa->sadb_sa_auth, ip->body + auth_len, ip->body, auth_len, (uint8_t*)sa->key_auth + sizeof(*sa->key_auth), sa->key_auth->sadb_key_bits / 8)) {
				return false;
			}
		}

		crypto_decrypt(sa->sa->sadb_sa_encrypt, esp->payload, len - ESP_HEADER_LEN, (uint8_t*)sa->key_encrypt + sizeof(*sa->key_encrypt), sa->key_encrypt->sadb_key_bits / 8); 

		return true;
	}

	bool ipsec_proof(SA* sa) {
		AH* ah = (AH*)ip->body;

		uint8_t ecn = ip->ecn;
		uint8_t dscp = ip->dscp;
		uint16_t flags_offset = ip->flags_offset;
		uint8_t ttl = ip->ttl;
		uint8_t auth_data[64];	//Max auth data length
		uint16_t auth_data_len = auth_auth_data_len(sa->sa->sadb_sa_auth);
		memcpy(auth_data, ah->auth_data, auth_data_len);

		ip->ecn = 0;
		ip->dscp = 0;
		ip->ttl = 0;
		ip->flags_offset = 0;
		ip->checksum = 0;
		memset(ah->auth_data, 0, auth_data_len);

		if(!auth_check(sa->sa->sadb_sa_auth, auth_data, (uint8_t*)ip, endian16(ip->length), (uint8_t*)sa->key_auth + sizeof(*sa->key_auth), sa->key_auth->sadb_key_bits / 8)) {
			return false;
		}

		ip->ecn = ecn;
		ip->dscp = dscp;
		ip->flags_offset = flags_offset;
		ip->ttl = ttl;

		return true;
	}

	bool inbound_esp_process(SA* sa) {
		if(!ipsec_decrypt(sa)) {
			return false;
		}

		dump_packet(packet);

		// unsetting Header
		ESP_T* esp_trailer = (ESP_T*)((uint8_t*)ip + endian16(ip->length) - (ip->ihl * 4) - ESP_TRAILER_LEN);
		switch(sa->x_sa2->sadb_x_sa2_mode) {
			case IPSEC_MODE_TUNNEL:
				//TODO length check
				if(!tunnel_unset(ESP_HEADER_LEN))
					return false;

				break;
			case IPSEC_MODE_TRANSPORT:
				//TODO length check
				//TODO add get iv len
				if(!transport_unset(ESP_HEADER_LEN))
					return false;

				dump_packet(packet);

				ip->protocol = esp_trailer->next_hdr;
				ip->checksum = 0;
				ip->checksum = endian16(checksum(ip, ip->ihl * 4));

				break;
			default:
				return false;
		}

		// unsetting Tail
		uint8_t tail_len = esp_trailer->pad_len + ESP_TRAILER_LEN;
		tail_unset(tail_len);

		return true;
	}

	bool inbound_ah_process(SA* sa) {
		if(!ipsec_proof(sa)) {
			return false;
		}

		// unsetting Header
		AH* ah = (AH*)ip->body;
		uint8_t header_len = (ah->len + 2) * 4;
		switch(sa->x_sa2->sadb_x_sa2_mode) {
			case IPSEC_MODE_TUNNEL:
				//TODO length check
				if(!tunnel_unset(header_len))
					return false;

				break;
			case IPSEC_MODE_TRANSPORT:
				//TODO length check
				ip->protocol = ah->next_hdr;
				if(!transport_unset(header_len))
					return false;

				ip->checksum = 0;
				ip->checksum = endian16(checksum(ip, ip->ihl * 4));

				break;
			default:
				return false;
		}
		return true;
	}
	/*
	   * TODO: Fix here
	   * First version don't support multi encryption and authentication.
	 */
	SA* sa = sapd_get_sa_inbound(sapd, ip);
	if(!sa) {
		printf("Can't found sa\n");
		return false;
	}
	switch(ip->protocol) {
		case IP_PROTOCOL_ESP:
			;
			printf("\tESP Process\n");
			if(!inbound_esp_process(sa))
				return false;
			break;

		case IP_PROTOCOL_AH:
			;
			printf("\tAH Process\n");
			if(!inbound_ah_process(sa))
				return false;
			break;
		default:
			return false;
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

	return true;
}

static bool outbound_process(SP* sp, Packet* packet) {
	Ether* ether = (Ether*)(packet->buffer + packet->start);
        IP* ip = (IP*)ether->payload;

	bool transport_set(uint16_t header_len) {
		if(packet->start > header_len) {
			ip->length = endian16(endian16(ip->length) + header_len);
			packet->start -= header_len;

			memmove(packet->buffer + packet->start, ether, ETHER_LEN + ip->ihl * 4);
			ether = (Ether*)(packet->buffer + packet->start);
			ip = (IP*)ether->payload;

			return true;
		} else if(packet->end + header_len < packet->size) {
			ip->length = endian16(endian16(ip->length) + header_len);
			memmove(ip->body + header_len, ip->body, ip->length - ip->ihl * 4 /* Body length*/);
			return true;
		} else if(packet->size > (packet->end - packet->start + header_len)) {
			//TODO fix here
			return false;
		} else {
			printf("Worst Case\n");
			return false;
		}

		return true;
	}

	bool tunnel_set(uint16_t header_len) {
		if((packet->start > (header_len + IP_LEN))) { 
			Ether* _ether = (Ether*)(packet->buffer + packet->start);
			IP* _ip = (IP*)_ether->payload;

			packet->start -= (IP_LEN + header_len);
			ether = (Ether*)(packet->buffer + packet->start);
			ip = (IP*)ether->payload;
			ip->ihl = IP_LEN / 4;
			ip->version = _ip->version;
			ip->ecn = _ip->ecn;
			ip->dscp = _ip->dscp;
			ip->length = endian16(endian16(_ip->length) + IP_LEN + header_len);
			ip->id = _ip->id;
			ip->flags_offset = _ip->flags_offset;

			return true;
		} else if(packet->end + IP_LEN + header_len < packet->size) {
			memmove(ip->body + header_len, ip, ip->length);

			ip->length = endian16(endian16(ip->length) + IP_LEN + header_len);
			packet->end += IP_LEN + header_len;

			return true;
		} else {
			printf("packet has not enough padding\n");
			return false;
		}

		return true;
	}

	bool tail_set(uint16_t tail_len) {
		if(packet->size > packet->end + tail_len) {
			unsigned char* padding = NULL;
			padding = packet->buffer + packet->end;
			for(int i = 0; i < tail_len; i++) {
				padding[i] = i + 1;
			}
			packet->end += tail_len;
		} else if(packet->start > tail_len) {
			memmove((uint8_t*)ether - tail_len, ether, packet->end - packet->start);
			packet->start -= tail_len;
			ether = (Ether*)(packet->buffer + packet->start);
			ip = (IP*)ether->payload;
		} else {
			printf("packet has not enough padding\n");
			return false;
		}
		return true;
	}

	bool outbound_esp_process(struct sadb_x_ipsecrequest* ipsecrequest, SA* sa) {
		// Setting tail for ESP -- Start
		uint16_t iv_len = crypto_get_iv_len(sa->sa->sadb_sa_encrypt);
		uint16_t padding_len = (endian16(ip->length) - (ip->ihl * 4) + ESP_TRAILER_LEN) % iv_len;
		if(padding_len != 0)
			padding_len = iv_len - padding_len;
		if(!tail_set(padding_len + ESP_TRAILER_LEN)) {
			return false;
		}

		ESP_T* esp_trailer = (ESP_T*)(ip->body + endian16(ip->length) - (ip->ihl * 4) - ESP_TRAILER_LEN);
		esp_trailer->pad_len = padding_len;
		switch(ipsecrequest->sadb_x_ipsecrequest_mode) {
			case IPSEC_MODE_TRANSPORT:
				esp_trailer->next_hdr = ip->protocol;
				break;
			case IPSEC_MODE_TUNNEL:
				esp_trailer->next_hdr = IP_PROTOCOL_IP;
				break;
		}
		// Setting tail for ESP -- End

		// Setting head for ESP -- Start
		switch(ipsecrequest->sadb_x_ipsecrequest_mode) {
			case IPSEC_MODE_TRANSPORT:
				if(!transport_set(ESP_HEADER_LEN)) {
					return false;
				}
				break;
			case IPSEC_MODE_TUNNEL:
				if(!tunnel_set(ESP_HEADER_LEN)) {
					return false;
				}
				ip->ttl = IPDEFTTL;
				struct sockaddr_in* sockaddr = (struct sockaddr_in*)((uint8_t*)ipsecrequest + sizeof(*ipsecrequest));
				ip->source = endian32(sockaddr->sin_addr.s_addr);
				sockaddr++;
				ip->destination = endian32(sockaddr->sin_addr.s_addr);
				break;
			default:
				return false;
		}
		// Setting head for ESP -- End

		// Setting IP Header
		ip->protocol = IP_PROTOCOL_ESP;
		ip->checksum = 0;
		ip->checksum = endian16(checksum(ip, ip->ihl * 4));

		// Request Encryption
		ESP* esp = (ESP*)ip->body;
		uint32_t length = endian16(ip->length) - (ip->ihl * 4) - ESP_HEADER_LEN;
		crypto_encrypt(sa->sa->sadb_sa_encrypt, esp->payload, length, (uint8_t*)sa->key_encrypt + sizeof(*sa->key_encrypt), sa->key_encrypt->sadb_key_bits / 8);
		esp->spi = sa->sa->sadb_sa_spi;
		esp->seq_num = 0;

		if(sa->sa->sadb_sa_auth != SADB_AALG_NONE) {
			//TODO Tail Length add AUTH_DATA_LEN
			uint16_t len = ip->length - (ip->ihl * 4);
			auth_request(sa->sa->sadb_sa_auth, ip->body + len, ip->body, len, (uint8_t*)sa->key_auth + sizeof(*sa->key_auth), sa->key_auth->sadb_key_bits / 8);
		}

		return true;
	}

	bool outbound_ah_process(struct sadb_x_ipsecrequest* ipsecrequest, SA* sa) {
		// Setting head for AH -- Start
		uint16_t auth_data_len = auth_auth_data_len(sa->sa->sadb_sa_auth);
		switch(ipsecrequest->sadb_x_ipsecrequest_mode) {
			case IPSEC_MODE_TRANSPORT:
				if(!transport_set(AH_HEADER_LEN + auth_data_len)) {
					return false;
				}
				break;
			case IPSEC_MODE_TUNNEL:
				if(!tunnel_set(AH_HEADER_LEN + auth_data_len)) {
					return false;
				}
				ip->ttl = IPDEFTTL;
				struct sockaddr_in* sockaddr = (struct sockaddr_in*)((uint8_t*)ipsecrequest + sizeof(*ipsecrequest));
				ip->source = endian32(sockaddr->sin_addr.s_addr);
				sockaddr++;
				ip->destination = endian32(sockaddr->sin_addr.s_addr);
				break;
			default:
				return false;
		}
		// Setting head for AH -- End

		// Setting IP Header
		ip->protocol = IP_PROTOCOL_AH;
		ip->checksum = 0;
		ip->checksum = endian16(checksum(ip, ip->ihl * 4));

		// Setting AH Header
		AH* ah = (AH*)ip->body;
		switch(ipsecrequest->sadb_x_ipsecrequest_mode) {
			case IPSEC_MODE_TRANSPORT:
				ah->next_hdr = ip->protocol;
				break;
			case IPSEC_MODE_TUNNEL:
				ah->next_hdr = IP_PROTOCOL_IP;
				break;
			default:
				return false;
		}
		ah->len = ((12 + auth_data_len) / 4) - 2;
		ah->spi = sa->sa->sadb_sa_spi;
		memset(ah->auth_data, 0, auth_data_len);

		// Request Authentication
		uint8_t ecn = ip->ecn;
		uint8_t dscp = ip->dscp;
		uint8_t ttl = ip->ttl;
		uint16_t flags_offset = ip->flags_offset;
		uint16_t checksum = ip->checksum;

		ip->ecn = 0;
		ip->dscp = 0;
		ip->ttl = 0;
		ip->flags_offset = 0;
		ip->checksum = 0;

		auth_request(sa->sa->sadb_sa_auth, ah->auth_data, (uint8_t*)ip, endian16(ip->length), (uint8_t*)sa->key_auth + sizeof(*sa->key_auth), sa->key_auth->sadb_key_bits / 8);

		ip->ecn = ecn;
		ip->dscp = dscp;
		ip->ttl = ttl;
		ip->flags_offset = flags_offset;
		ip->checksum = checksum;

		return true;
	}

	int len = sp->policy->sadb_x_policy_len * 8 - sizeof(*sp->policy);
	struct sadb_x_ipsecrequest* ipsecrequest = (struct sadb_x_ipsecrequest*)((uint8_t*)sp->policy + sizeof(struct sadb_x_ipsecrequest));
	while(len) {
		SA* sa = sp_get_sa_cache(sp, ip);

		if(!sa)
			sa = sapd_get_sa_outbound(sapd, ipsecrequest, ip);

		if(!sa) {
			return false;
		}

		switch(ipsecrequest->sadb_x_ipsecrequest_proto) {
			case IP_PROTOCOL_ESP:
				printf("\tESP Process\n");
				outbound_esp_process(ipsecrequest, sa);
				break;
			case IP_PROTOCOL_AH:
				printf("\tAH Process\n");
				outbound_ah_process(ipsecrequest, sa);
				break;
		}

		len -= ipsecrequest->sadb_x_ipsecrequest_len;
		ipsecrequest = (struct sadb_x_ipsecrequest*)((uint8_t*)ipsecrequest + ipsecrequest->sadb_x_ipsecrequest_len * 8);
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
			
		if(!!sp && sp->policy->sadb_x_policy_dir == IPSEC_DIR_OUTBOUND) {
			printf("Outbound Process\n");
			if(!outbound_process(sp, packet)) { 
				nic_free(packet);
				return true;
			}
		} else {
			printf("Inbound Process\n");
			if(!inbound_process(packet)) {
				nic_free(packet);
				return true;
			}
		}

		printf("Route Process\n");
		if(!route_process(packet))
			nic_free(packet);

		return true;
	}

	return false;
}
