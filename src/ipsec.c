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

#include "ipsec.h"
#include "esp.h"
#include "ah.h"
#include "socket.h"
#include "spd.h"
#include "sad.h"
#include "ike.h"
#include "mode.h"

Map* global_map;

bool ipsec_ginit() {
	printf("PacketNgin IPSec\n\n");
	int id = thread_id();
	if(id != 0)
		return false;

	extern void* __gmalloc_pool;
	Map* map = map_create(8, map_string_hash, map_string_equals, __gmalloc_pool);
	if(!map) {
		return false;
	}
	shared_set(map);

	printf("Initialize SAD...\n");
	if(!sad_ginit()) {
		printf("Initializing SAD is fail!!!\n");
		return false;
	}
	printf("SAD initialized\n\n");

	printf("Initialize SPD...\n");
	if(!spd_ginit()) {
		printf("Initializing SPD is fail!!!\n");
		return false;
	}
	printf("SPD initialized\n\n");

	if(!socket_ginit()) {
		printf("Initializing Sockets is fail!!!\n");
		return false;
	}
	printf("Socket initialized\n\n");

	printf("PacketNgin IPSec Start\n");

	return true;
}

bool ipsec_init() {
	global_map = shared_get();

	event_init();

	return true;
}

void ipsec_destroy() {
	//TODO: Fix event api
	//event_destroy();
}

void ipsec_gdestroy() {
	printf("Destroy IPSec...\n");

	int id = thread_id();
	if(id != 0)
		return;

	socket_gdestroy();

	spd_gdestroy();

	sad_gdestroy();
	
	map_destroy(global_map);
}

static bool ipsec_decrypt(Packet* packet, SA* sa) { 
	Ether* ether = (Ether*)(packet->buffer + packet->start);
        IP* ip = (IP*)ether->payload;

	// 2. Seq# Validation
	ESP* esp = (ESP*)ip->body;
	
	if(((SA_ESP*)sa)->auth) {
		if(!((Authentication*)(((SA_ESP*)sa)->auth))->authenticate(packet, sa, AUTH_CHECK)) {
			return false;
		}
	}
	int size = endian16(ip->length) - (ip->ihl * 4);

	((Cryptography*)(((SA_ESP*)sa)->crypto))->decrypt(esp, size, (SA_ESP*)sa); 
	
	// 5. ESP Header & Trailer Deletion
	ESP_T* esp_trailer = (ESP_T*)(ip->body + endian16(ip->length) - (ip->ihl * 4) - ESP_TRAILER_LEN);
	uint8_t padding_len = esp_trailer->pad_len;
	if(sa->ipsec_mode == IPSEC_MODE_TRANSPORT) {
		//TODO length check
		ip->protocol = esp_trailer->next_hdr;
		ip->ttl--;
		if(!transport_unset(packet, ESP_HEADER_LEN + ((Cryptography*)(((SA_ESP*)sa)->crypto))->iv_len, padding_len + ESP_TRAILER_LEN))
			return false;

		ether = (Ether*)(packet->buffer + packet->start);
		ip = (IP*)ether->payload;

		ip->checksum = 0;
		ip->checksum = endian16(checksum(ip, ip->ihl * 4));

		return true;
	} else if(sa->ipsec_mode == IPSEC_MODE_TUNNEL) {
		//TODO length check
		return tunnel_unset(packet, ESP_HEADER_LEN + ((Cryptography*)(((SA_ESP*)sa)->crypto))->iv_len, padding_len + ESP_TRAILER_LEN);
	} else
		return false;
}

static bool ipsec_encrypt(Packet* packet, Content* content, SA* sa) {
	Ether* ether = (Ether*)(packet->buffer + packet->start);
        IP* ip = (IP*)ether->payload;

	uint16_t padding_len = 0;
	if(content->ipsec_mode == IPSEC_MODE_TRANSPORT) {
		padding_len = (endian16(ip->length) - (ip->ihl * 4) + ESP_TRAILER_LEN) % ((Cryptography*)(((SA_ESP*)sa)->crypto))->iv_len;

		if(padding_len != 0)
			padding_len = ((Cryptography*)(((SA_ESP*)sa)->crypto))->iv_len - padding_len;

		if(!transport_set(packet, ESP_HEADER_LEN + ((Cryptography*)(((SA_ESP*)sa)->crypto))->iv_len, padding_len + ESP_TRAILER_LEN))
			return false;
	} else if(content->ipsec_mode == IPSEC_MODE_TUNNEL) {
		padding_len = (endian16(ip->length) + ESP_TRAILER_LEN) % ((Cryptography*)(((SA_ESP*)sa)->crypto))->iv_len;

		if(padding_len != 0)
			padding_len = ((Cryptography*)(((SA_ESP*)sa)->crypto))->iv_len - padding_len;

		if(!tunnel_set(packet, ESP_HEADER_LEN + ((Cryptography*)(((SA_ESP*)sa)->crypto))->iv_len, padding_len + ESP_TRAILER_LEN))
			return false;
	}

	ether = (Ether*)(packet->buffer + packet->start);
        ip = (IP*)ether->payload;
	//Set ESP Trailer
	ESP_T* esp_trailer = (ESP_T*)(ip->body + endian16(ip->length) - (ip->ihl * 4) - ESP_TRAILER_LEN);
	esp_trailer->pad_len = padding_len;
	if(content->ipsec_mode == IPSEC_MODE_TRANSPORT) {
		esp_trailer->next_hdr = ip->protocol;
	} else if(content->ipsec_mode == IPSEC_MODE_TUNNEL) {
		esp_trailer->next_hdr = IP_PROTOCOL_IP;
	}

	ESP* esp = (ESP*)ip->body;
	// 5. Seq# Validation
	((Cryptography*)(((SA_ESP*)sa)->crypto))->encrypt(esp, endian16(ip->length) - (ip->ihl * 4) - ESP_HEADER_LEN, (SA_ESP*)sa);
	esp->seq_num = endian32(window_get_seq_counter(sa->window));
	esp->spi = endian32(sa->spi);
	
	if(((SA_ESP*)sa)->auth) {
		((Authentication*)(((SA_ESP*)sa)->auth))->authenticate(packet, sa, AUTH_REQUEST);
	}

	ip->protocol = IP_PROTOCOL_ESP;

	switch(content->ipsec_mode) {
		case IPSEC_MODE_TRANSPORT:
			ip->ttl--;
			ip->checksum = 0;
			ip->checksum = endian16(checksum(ip, ip->ihl * 4));
			break;
		case IPSEC_MODE_TUNNEL:
			ip->ttl = IP_TTL;
			ip->source = endian32(((Content_ESP_Tunnel*)content)->t_src_ip);
			ip->destination = endian32(((Content_ESP_Tunnel*)content)->t_dest_ip);
			ip->checksum = 0;
			ip->checksum = endian16(checksum(ip, ip->ihl * 4));
			break;
	}

	return true;
}

//Check auth
static bool ipsec_proof(Packet* packet, SA* sa) {
	Ether* ether = (Ether*)(packet->buffer + packet->start);
        IP* ip = (IP*)ether->payload;
	AH* ah = (AH*)ip->body;

	if(!((Authentication*)(((SA_AH*)sa)->auth))->authenticate(packet, sa, AUTH_CHECK)) {
		return false;
	}

	if(ah->next_hdr == IP_PROTOCOL_IP && sa->ipsec_mode == IPSEC_MODE_TUNNEL) {
		//Tunnel mode
		return tunnel_unset(packet, (ah->len + 2) * 4, 0);
	} else if(sa->ipsec_mode == IPSEC_MODE_TRANSPORT) {
		//Transport mode
		ip->protocol = ah->next_hdr;

		if(!transport_unset(packet, (ah->len + 2) * 4, 0))
			return false;

		ether = (Ether*)(packet->buffer + packet->start);
		ip = (IP*)ether->payload;
		ip->checksum = endian16(checksum(ip, ip->ihl * 4));
	} else
		return false;

	return true;
}

static bool ipsec_auth(Packet* packet, Content* content, SA* sa) {
	Ether* ether = NULL;
        IP* ip = NULL;
	AH* ah = NULL;

	if(content->ipsec_mode == IPSEC_MODE_TRANSPORT) {
		if(!transport_set(packet, 12 + ((Authentication*)(((SA_AH*)sa)->auth))->auth_len, 0))
			return false;

		ether = (Ether*)(packet->buffer + packet->start);
		ip = (IP*)ether->payload;
		ah = (AH*)ip->body;

		//ip->length = endian16(endian16(ip->length) + AH_HEADER_LEN + ICV_LEN);
		ah->next_hdr = ip->protocol;
	} else if(content->ipsec_mode == IPSEC_MODE_TUNNEL) {
		if(!tunnel_set(packet, 12 + ((Authentication*)(((SA_AH*)sa)->auth))->auth_len, 0))
			return false;

		ether = (Ether*)(packet->buffer + packet->start);
		ip = (IP*)ether->payload;
		ah = (AH*)ip->body;

		//ip->length = endian16(endian16(ip->length) + IP_LEN + AH_HEADER_LEN + ICV_LEN);
		ah->next_hdr = IP_PROTOCOL_IP;
	}

	ah->len = ((12 + ((Authentication*)(((SA_AH*)sa)->auth))->auth_len) / 4) - 2;
	ah->spi = endian32(sa->spi);
	ah->seq_num = endian32(++sa->window->seq_counter);

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

	if(content->ipsec_mode == IPSEC_MODE_TUNNEL) {
			ip->source = endian32(((Content_AH_Tunnel*)content)->t_src_ip);
			ip->destination = endian32(((Content_AH_Tunnel*)content)->t_dest_ip);
	}

	((Authentication*)(((SA_AH*)sa)->auth))->authenticate(packet, sa, AUTH_REQUEST);

	switch(content->ipsec_mode) {
		case IPSEC_MODE_TRANSPORT:
			ip->ttl = ttl - 1;
			break;
		case IPSEC_MODE_TUNNEL:
			ip->ttl = IP_TTL;
			break;
	}
	ip->ecn = ecn;
	ip->dscp = dscp;
	ip->ttl = ttl;
	ip->flags_offset = flags_offset;


	ip->checksum = endian16(checksum(ip, ip->ihl * 4));

	return true;
}

static bool inbound_process(Packet* packet) {
	Ether* ether = (Ether*)(packet->buffer + packet->start);
        IP* ip = (IP*)ether->payload;

	NetworkInterface* ni = packet->ni;
	List* sa_list = list_create(ni->pool);
	SA* sa = NULL;
	spd_inbound_rlock(ni);
	sad_rlock(ni);
	while((ip->protocol == IP_PROTOCOL_ESP) || (ip->protocol == IP_PROTOCOL_AH)) {
		switch(ip->protocol) {
			case IP_PROTOCOL_ESP:
				;
				ESP* esp = (ESP*)ip->body;
				sa = sad_get_sa(ni, endian32(esp->spi), endian32(ip->destination), ip->protocol);
				if(!sa) {
					goto error;
				}
				if(!ipsec_decrypt(packet, sa)) {
					goto error;
				}
				break;

			case IP_PROTOCOL_AH:
				;
				AH* ah = (AH*)ip->body;
				sa = sad_get_sa(ni, endian32(ah->spi), endian32(ip->destination), ip->protocol);
				if(!sa) {
					goto error;
				}
				if(!ipsec_proof(packet, sa)) {
					goto error;
				}
				break;
		}

		list_add_at(sa_list, 0, sa);
		ether = (Ether*)(packet->buffer + packet->start);
		ip = (IP*)ether->payload;
	}

	// 6. SPD Lookup 
	SP* sp = spd_get_sp(ni, DIRECTION_IN, ip);
	if(!sp) {
		goto error;
	}

	// 7. Verification
	if(!sp_verify_sa(sp, sa_list, ip)) {
		goto error;
	}

	ether = (Ether*)(packet->buffer + packet->start);
        ip = (IP*)ether->payload;
	ether->smac = endian48(sp->out_ni->mac);

	Map* interfaces = ni_config_get(sp->out_ni, NI_ADDR_IPv4);
	IPv4Interface* interface = NULL;
	IPv4Interface* default_interface = NULL;
	uint32_t default_interface_addr;
	MapIterator iter;
	map_iterator_init(&iter, interfaces);
	while(map_iterator_has_next(&iter)) {
		MapEntry* entry = map_iterator_next(&iter);
		interface = entry->data;
		if((endian32(ip->destination) & interface->netmask) == ((uint32_t)(uint64_t)entry->key & interface->netmask)) {
			ether->dmac = endian48(arp_get_mac(sp->out_ni, endian32(ip->destination), (uint32_t)(uint64_t)entry->key));
			goto next;
		} else if(interface->_default == true) {
			default_interface = interface;
			default_interface_addr = (uint32_t)(uint64_t)entry->key;
		}

	}

	if(default_interface)
		ether->dmac = endian48(arp_get_mac(sp->out_ni, default_interface->gateway, default_interface_addr));
	else
		goto error;

next:
	ether->type = endian16(ETHER_TYPE_IPv4);

	ni_output(sp->out_ni, packet);
	spd_inbound_un_rlock(ni);
	sad_un_rlock(ni);
	list_destroy(sa_list);

	return true;

error:
	ni_free(packet);
	spd_inbound_un_rlock(ni);
	sad_un_rlock(ni);
	list_destroy(sa_list);

	return true;
}

static bool outbound_process(Packet* packet) {
	NetworkInterface* ni = packet->ni;
	Ether* ether = (Ether*)(packet->buffer + packet->start);
        IP* ip = (IP*)ether->payload;
	
	Socket* socket = NULL;
	SP* sp = NULL;
	SA* sa = NULL;

	spd_outbound_rlock(ni);
	sad_rlock(ni);
	if(ip->protocol == IP_PROTOCOL_TCP) { //tcp use socket pointer 
		TCP* tcp = (TCP*)ip->body;
		socket = socket_get(ni, endian32(ip->source), endian16(tcp->source), endian32(ip->destination), endian16(tcp->destination));
		if(socket) {
			/*This Packet Is TCP Packet*/
			sp = socket->sp;
			sa = socket->sa;
			if(tcp->fin) {
				socket->fin = true;
				bool delete_socket(void* context) {
					//delete socket
					return false;
				}
				event_timer_add(delete_socket, socket, 5000000, 5000000);
				//socket free
				//TODO timer event
				//socket_delete(endian32(ip->source), endian16(tcp->source));
			}
			goto tcp_packet;
		}
	}

	if(!sp)
		sp = spd_get_sp(packet->ni, DIRECTION_OUT, ip);

	if(!sp) {
		spd_outbound_un_rlock(ni);
		sad_un_rlock(ni);
		return false;
	}

tcp_packet:
	if(sp->ipsec_action == IPSEC_ACTION_BYPASS) {
		if((ip->protocol == IP_PROTOCOL_TCP && !socket)) {
			TCP* tcp = (TCP*)ip->body;
			socket = socket_create(ni, sp, NULL);
			socket_add(ni, endian32(ip->source), endian16(tcp->source), endian32(ip->destination), endian16(tcp->destination), socket);
		}
		
		ether->smac = endian48(sp->out_ni->mac);

		IPv4Interface* interface = ni_ip_get(sp->out_ni, endian32(ip->source));
		if(!interface) {
			Map* interfaces = ni_config_get(ni, NI_ADDR_IPv4);
			MapIterator iter;
			map_iterator_init(&iter, interfaces);
			while(map_iterator_has_next(&iter)) {
				MapEntry* entry = map_iterator_next(&iter);
				interface = entry->data;
				if(interface->_default) {
					ether->dmac = endian48(arp_get_mac(sp->out_ni, interface->gateway, (uint32_t)(uint64_t)entry->key));
					goto next;
				}
			}

			ni_free(packet);
			spd_inbound_un_rlock(ni);
			sad_un_rlock(ni);

			return true;
		} else {
			if((endian32(ip->destination) & interface->netmask) == (endian32(ip->source) & interface->netmask)) {
				ether->dmac = endian48(arp_get_mac(sp->out_ni, endian32(ip->destination), endian32(ip->source)));
			} else {
				ether->dmac = endian48(arp_get_mac(sp->out_ni, interface->gateway, endian32(ip->source)));
			}
		}
	}

	if(!sa) {
		sa = sp_get_sa(sp, ip);
	}

	if(!sa) {
		sa = sp_find_sa(sp, ip);
	}

	if(!sa) {
		sa = ike_sa_get(ip, sp); //this function not work;
	}

	if(!sa) {
		ni_free(packet);
		spd_outbound_un_rlock(ni);
		sad_un_rlock(ni);

		return true;
	}

	if(ip->protocol == IP_PROTOCOL_TCP) {
		TCP* tcp = (TCP*)ip->body;
		Socket* socket = socket_create(ni, sp, sa);
		socket_add(ni, endian32(ip->source), endian16(tcp->source), endian32(ip->destination), endian16(tcp->destination), socket);
	}

	ListIterator iter;
	list_iterator_init(&iter, sp->contents);
	while(list_iterator_has_next(&iter)) {
		Content* content = list_iterator_next(&iter);

		if(!sa) {
			ni_free(packet);
			spd_outbound_un_rlock(ni);
			sad_un_rlock(ni);

			return true;
		}

		switch(content->ipsec_protocol) {
			case IP_PROTOCOL_ESP:
				if(!ipsec_encrypt(packet, content, sa)) {
					ni_free(packet);
					spd_outbound_un_rlock(ni);
					sad_un_rlock(ni);

					return true;
				}
				break;

			case IP_PROTOCOL_AH:
				if(!ipsec_auth(packet, content, sa)) {
					ni_free(packet);
					spd_outbound_un_rlock(ni);
					sad_un_rlock(ni);

					return true;
				}
				break;
		}

		sa = sa->next;
	}

	ether = (Ether*)(packet->buffer + packet->start);
        ip = (IP*)ether->payload;
	ether->smac = endian48(sp->out_ni->mac);
	IPv4Interface* interface = ni_ip_get(sp->out_ni, endian32(ip->source));
	if(!interface) {
		Map* interfaces = ni_config_get(ni, NI_ADDR_IPv4);
		MapIterator iter;
		map_iterator_init(&iter, interfaces);
		while(map_iterator_has_next(&iter)) {
			MapEntry* entry = map_iterator_next(&iter);
			interface = entry->data;
			if(interface->_default) {
				ether->dmac = endian48(arp_get_mac(sp->out_ni, interface->gateway, (uint32_t)(uint64_t)entry->key));
				goto next;
			}
		}

		ni_free(packet);
		spd_inbound_un_rlock(ni);
		sad_un_rlock(ni);

		return true;
	} else {
		if((endian32(ip->destination) & interface->netmask) == (endian32(ip->source) & interface->netmask)) {
			ether->dmac = endian48(arp_get_mac(sp->out_ni, endian32(ip->destination), endian32(ip->source)));
		} else {
			ether->dmac = endian48(arp_get_mac(sp->out_ni, interface->gateway, endian32(ip->source)));
		}
	}
next:
	ether->type = endian16(ETHER_TYPE_IPv4);
	ni_output(sp->out_ni, packet);
	spd_outbound_un_rlock(ni);
	sad_un_rlock(ni);

	return true;
}

bool ipsec_process(Packet* packet) {
	//event_loop();

	if(arp_process(packet))
		return true;

 	if(icmp_process(packet))
 		return true;

	Ether* ether = (Ether*)(packet->buffer + packet->start);
	if(endian16(ether->type) == ETHER_TYPE_IPv4) {
		//verify IPv4 length
		IP* ip = (IP*)ether->payload;
		if(endian16(ip->length) != (packet->end - packet->start - ETHER_LEN)) {
			return false;
		}

		if(outbound_process(packet)) {
			return true;
		}

		if(inbound_process(packet)) {
			return true;
		}
	}

	return false;
}
