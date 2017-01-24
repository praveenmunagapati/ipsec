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
	for(int i = packet->start; i < packet->end;) {
		for(int j = 0; i < packet->end && j < 32; j++, i++)
			printf("%02x", *(uint8_t*)(packet->buffer + i));
		printf("\n");
	}
}

static bool inbound_process(Packet* packet) {
	Ether* ether = (Ether*)(packet->buffer + packet->start);
        IP* ip = (IP*)ether->payload;

	bool ipsec_header_unset(uint16_t header_len) {
		memmove((uint8_t*)ether + header_len, ether, ETHER_LEN + (ip->ihl * 4));

		packet->start += header_len;
		ether = (Ether*)((uint8_t*)ether + header_len);
		ip = (IP*)((uint8_t*)ip + header_len);
		ip->length = endian16(endian16(ip->length) - header_len);

		return true;
	}

	bool tunnel_unset() {
		packet->start += (ip->ihl * 4);
		ether = (Ether*)(packet->buffer + packet->start);
		ether->dmac = endian48(0xffffffffffff);
		ether->smac = endian48(0xffffffffffff);
		ether->type = endian16(ETHER_TYPE_IPv4);
		ip = (IP*)ether->payload;
		
		return true;
	}

	bool tail_unset(uint16_t tail_len) {
		if((endian16(ip->length) - ip->ihl * 4) < tail_len)
			return false;

		packet->end -= tail_len;
		ip->length = endian16(endian16(ip->length) - tail_len);
		return true;
	}

	bool inbound_esp_process(SA* sa) {
		ESP* esp = (ESP*)ip->body;

		// Authenticate -- Start
		if(sa->sa->sadb_sa_auth != SADB_EALG_NONE) {
			uint16_t authdata_len = auth_get_authdata_len(sa->sa->sadb_sa_auth);
			uint16_t auth_len = endian16(ip->length) - ip->ihl * 4 - authdata_len;
			if(sa->key_auth) {
				if(!auth_check(sa->sa->sadb_sa_auth, ip->body + auth_len, authdata_len, ip->body, auth_len, (uint8_t*)sa->key_auth + sizeof(*sa->key_auth), sa->key_auth->sadb_key_bits / 8)) {
					return false;
				}
			} else if(!auth_check(sa->sa->sadb_sa_auth, ip->body + auth_len, authdata_len, ip->body, auth_len, NULL, 0)) {
					return false;
			}

			if(!tail_unset(authdata_len)) {
				return false;
			}
		}

		// Decryption
		uint16_t len = endian16(ip->length) - ip->ihl * 4; //ip body len
		if(sa->key_encrypt)
			crypto_decrypt(sa->sa->sadb_sa_encrypt, esp->payload, len - ESP_HEADER_LEN, (uint8_t*)sa->key_encrypt + sizeof(*sa->key_encrypt), sa->key_encrypt->sadb_key_bits / 8); 
		else
			crypto_decrypt(sa->sa->sadb_sa_encrypt, esp->payload, len - ESP_HEADER_LEN, NULL, 0); 

		// Unsetting IPSec Header
		ESP_T* esp_trailer = (ESP_T*)((uint8_t*)ip + endian16(ip->length) - ESP_TRAILER_LEN);
		ip->protocol = esp_trailer->next_hdr;
		int iv_len = crypto_get_iv_len(sa->sa->sadb_sa_encrypt);
		if(!ipsec_header_unset(ESP_HEADER_LEN + iv_len))
			return false;

		// unsetting Tail
		uint8_t tail_len = esp_trailer->pad_len + ESP_TRAILER_LEN;
		if(!tail_unset(tail_len)) {
			return false;
		}

		return true;
	}

	bool inbound_ah_process(SA* sa) {
		AH* ah = (AH*)ip->body;

		uint8_t ecn = ip->ecn;
		uint8_t dscp = ip->dscp;
		uint16_t flags_offset = ip->flags_offset;
		uint8_t ttl = ip->ttl;
		uint8_t icv[64];	//Max auth data length
		uint16_t icv_len = auth_get_icv_len(sa->sa->sadb_sa_auth);
		uint16_t authdata_len = auth_get_authdata_len(sa->sa->sadb_sa_auth);
		memcpy(icv, ah->auth_data, icv_len);

		ip->ecn = 0;
		ip->dscp = 0;
		ip->ttl = 0;
		ip->flags_offset = 0;
		ip->checksum = 0;

		memset(ah->auth_data, 0, authdata_len);

		if(sa->key_auth) {
			if(!auth_check(sa->sa->sadb_sa_auth, icv, authdata_len, (uint8_t*)ip, endian16(ip->length), (uint8_t*)sa->key_auth + sizeof(*sa->key_auth), sa->key_auth->sadb_key_bits / 8)) {
				return false;
			}
		} else {
			if(!auth_check(sa->sa->sadb_sa_auth, icv, authdata_len, (uint8_t*)ip, endian16(ip->length), NULL, 0)) {
				return false;
			}
		}

		ip->ecn = ecn;
		ip->dscp = dscp;
		ip->flags_offset = flags_offset;
		ip->ttl = ttl;

		// Unsetting IPSec Header
		uint8_t header_len = (ah->len + 2) * 4;
		ip->protocol = ah->next_hdr;
		if(!ipsec_header_unset(header_len))
			return false;

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

	// Unsetting Tunnel
	if(sa->x_sa2->sadb_x_sa2_mode == IPSEC_MODE_TUNNEL) {
		if(!tunnel_unset())
			return false;
	}

	ip->checksum = 0;
	ip->checksum = endian16(checksum(ip, ip->ihl * 4));

	SP* sp = sapd_get_sp(sapd, IPSEC_POLICY_IPSEC, ip);
	if(!sp) {
		return false;
	}

	return true;
}

static bool outbound_process(SP* sp, Packet* packet) {
	Ether* ether = (Ether*)(packet->buffer + packet->start);
        IP* ip = (IP*)ether->payload;

	bool ipsec_header_set(uint16_t header_len) {
		if(packet->start < header_len)
			return false;

		ip->length = endian16(endian16(ip->length) + header_len);
		packet->start -= header_len;

		memmove(packet->buffer + packet->start, ether, ETHER_LEN + ip->ihl * 4);
		ether = (Ether*)(packet->buffer + packet->start);
		ip = (IP*)ether->payload;
		return true;
	}

	bool tunnel_set() {
		if(packet->start <= IP_LEN)
			return false;

	
		IP* _ip = ip;

		packet->start -= IP_LEN;
		ether = (Ether*)(packet->buffer + packet->start);
		ether->dmac = endian48(0xffffffffffff);
		ether->smac = endian48(0xffffffffffff);
		ether->type = endian16(ETHER_TYPE_IPv4);
		ip = (IP*)ether->payload;
		ip->ihl = IP_LEN / 4;
		ip->version = _ip->version;
		ip->ecn = _ip->ecn;
		ip->dscp = _ip->dscp;
		ip->length = endian16(endian16(_ip->length) + IP_LEN);
		ip->id = _ip->id;
		ip->flags_offset = _ip->flags_offset;

		return true;
	}

	bool tail_set(uint16_t tail_len) {
		if(packet->size - packet->end < tail_len)
			return false;

		packet->end += tail_len;
		ip->length = endian16(endian16(ip->length) + tail_len);
		return true;
	}

	bool outbound_esp_process(struct sadb_x_ipsecrequest* ipsecrequest, SA* sa) {
		// Setting tail for ESP -- Start
		uint16_t iv_len = crypto_get_iv_len(sa->sa->sadb_sa_encrypt);
		uint16_t padding_len = 0;
		if(iv_len)
			 padding_len = (endian16(ip->length) - (ip->ihl * 4) + ESP_TRAILER_LEN) % iv_len;
		if(padding_len != 0)
			padding_len = iv_len - padding_len;
		if(!tail_set(padding_len + ESP_TRAILER_LEN)) {
			return false;
		}

		ESP_T* esp_trailer = (ESP_T*)((uint8_t*)ip + endian16(ip->length) - ESP_TRAILER_LEN);
		esp_trailer->pad_len = padding_len;
		esp_trailer->next_hdr = ip->protocol;
		// Setting tail for ESP -- End

		// Setting head for ESP -- Start
		if(!ipsec_header_set(ESP_HEADER_LEN + iv_len)) {
			return false;
		}
		ip->protocol = IP_PROTOCOL_ESP;
		// Setting head for ESP -- End

		// Request Encryption
		ESP* esp = (ESP*)ip->body;
		uint32_t length = endian16(ip->length) - (ip->ihl * 4) - ESP_HEADER_LEN;
		if(sa->key_encrypt)
			crypto_encrypt(sa->sa->sadb_sa_encrypt, esp->payload, length, (uint8_t*)sa->key_encrypt + sizeof(*sa->key_encrypt), sa->key_encrypt->sadb_key_bits / 8);
		else
			crypto_encrypt(sa->sa->sadb_sa_encrypt, esp->payload, length, NULL, 0);
		esp->spi = sa->sa->sadb_sa_spi;
		esp->seq_num = 0;

		// Authenticate -- Start
		if(sa->sa->sadb_sa_auth != SADB_AALG_NONE) {
			uint16_t len = endian16(ip->length) - (ip->ihl * 4);
			uint16_t authdata_len = auth_get_authdata_len(sa->sa->sadb_sa_auth);
			if(!tail_set(authdata_len))
				return false;

			if(sa->key_auth)
				auth_request(sa->sa->sadb_sa_auth, ip->body + len, authdata_len, ip->body, len, (uint8_t*)sa->key_auth + sizeof(*sa->key_auth), sa->key_auth->sadb_key_bits / 8);
			else
				auth_request(sa->sa->sadb_sa_auth, ip->body + len, authdata_len, ip->body, len, NULL, 0);
		}
		// Authenticate -- End

		// Setting IP Header
		ip->checksum = 0;
		ip->checksum = endian16(checksum(ip, ip->ihl * 4));

		return true;
	}

	bool outbound_ah_process(struct sadb_x_ipsecrequest* ipsecrequest, SA* sa) {
		// Setting head for AH -- Start
		uint16_t icv_len = auth_get_icv_len(sa->sa->sadb_sa_auth);
		uint16_t authdata_len = auth_get_authdata_len(sa->sa->sadb_sa_auth);
		if(!ipsec_header_set(AH_HEADER_LEN + icv_len)) {
			return false;
		}
		// Setting head for AH -- End

		// Setting AH Header
		AH* ah = (AH*)ip->body;
		ah->next_hdr = ip->protocol;
		ah->len = ((12 + icv_len) / 4) - 2;
		ah->spi = sa->sa->sadb_sa_spi;
		ah->reserved = 0;
		ah->seq_num = 0;
		memset(ah->auth_data, 0, icv_len);

		// Setting IP Header
		ip->protocol = IP_PROTOCOL_AH;
		ip->checksum = 0;
		ip->checksum = endian16(checksum(ip, ip->ihl * 4));

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

		if(sa->key_auth)
			auth_request(sa->sa->sadb_sa_auth, ah->auth_data, authdata_len, (uint8_t*)ip, endian16(ip->length), (uint8_t*)sa->key_auth + sizeof(*sa->key_auth), sa->key_auth->sadb_key_bits / 8);
		else
			auth_request(sa->sa->sadb_sa_auth, ah->auth_data, authdata_len, (uint8_t*)ip, endian16(ip->length), 0, 0);

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
		if(ipsecrequest->sadb_x_ipsecrequest_mode == IPSEC_MODE_TUNNEL) {
			if(!tunnel_set()) {
				return false;
			}
			ip->ttl = IPDEFTTL;
			struct sockaddr_in* sockaddr = (struct sockaddr_in*)((uint8_t*)ipsecrequest + sizeof(*ipsecrequest));
			ip->source = sockaddr->sin_addr.s_addr;
			sockaddr++;
			ip->destination = sockaddr->sin_addr.s_addr;
			ip->protocol = IP_PROTOCOL_IP;
		}

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

		SP* sp = sapd_get_sp(sapd, IPSEC_POLICY_IPSEC, ip);
			
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
