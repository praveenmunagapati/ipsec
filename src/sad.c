#include <stdio.h>
#include <stdbool.h>
#include <malloc.h>
#define DONT_MAKE_WRAPPER
#include <_malloc.h>
#undef DONT_MAKE_WRAPPER
#include <string.h>
#include <util/map.h>
#include <netinet/in.h>
#include <net/ether.h>

#include "esp.h"
#include "ah.h"
#include "sad.h"

#include <byteswap.h>

extern void* __gmalloc_pool;
SAD* sad_create() {
	SAD* sad = __malloc(sizeof(SAD), __gmalloc_pool);
	memset(sad, 0, sizeof(SAD));
	sad->database = map_create(1024, NULL, NULL, __gmalloc_pool);
	if(!sad->database)
		goto fail;
	rwlock_init(&sad->rwlock);

	return sad;
fail:

	if(sad->database)
		map_destroy(sad->database);
	__free(sad, __gmalloc_pool);

	return NULL;
}

void sad_delete(SAD* sad) {
	//TODO Check is empty
	__free(sad, __gmalloc_pool);
}

void sad_flush(SAD* sad) {
	rwlock_wlock(&sad->rwlock);
	MapIterator iter;
	map_iterator_init(&iter, sad->database);
	while(map_iterator_has_next(&iter)) {
		MapEntry* entry = map_iterator_next(&iter);
		Map* _sad = entry->data;

		MapIterator iter2;
		map_iterator_init(&iter2, _sad);
		while(map_iterator_has_next(&iter2)) {
			MapEntry* entry2 = map_iterator_next(&iter2);
			SA* sa = entry2->data;
#ifdef DEBUG
			sa_dump(sa);
#endif
			sa_free(sa);
			map_iterator_remove(&iter2);
		}
		map_iterator_remove(&iter);
		map_destroy(_sad);
	}
	rwlock_wunlock(&sad->rwlock);
}

SA* sad_get_sa_outbound(SAD* sad, struct sadb_x_ipsecrequest* ipsecrequest, IP* ip) {
	rwlock_rlock(&sad->rwlock);
	MapIterator iter;
	map_iterator_init(&iter, sad->database);
	while(map_iterator_has_next(&iter)) {
		MapEntry* entry = map_iterator_next(&iter);
		Map* _sad = entry->data;

		MapIterator iter2;
		map_iterator_init(&iter2, _sad);
		while(map_iterator_has_next(&iter2)) {
			MapEntry* entry2 = map_iterator_next(&iter2);
			SA* sa = entry2->data;
			//check mode
			if(sa->x_sa2->sadb_x_sa2_mode != ipsecrequest->sadb_x_ipsecrequest_mode)
				continue;

			//check protocol
			if(!((sa->sadb_msg->sadb_msg_satype == SADB_SATYPE_AH) && ipsecrequest->sadb_x_ipsecrequest_proto == IP_PROTOCOL_AH) &&
				!((sa->sadb_msg->sadb_msg_satype == SADB_SATYPE_ESP) && ipsecrequest->sadb_x_ipsecrequest_proto == IP_PROTOCOL_ESP))
				continue;

			//Add mask
			struct sockaddr_in* src_sockaddr = (struct sockaddr_in*)((uint8_t*)sa->address_src + sizeof(*sa->address_src));
			uint32_t src_mask = (uint32_t)0xffffffff >> (32 - sa->address_src->sadb_address_prefixlen);
			uint32_t s_addr = src_sockaddr->sin_addr.s_addr;
			if((s_addr & src_mask) != (ip->source & src_mask)) {
				continue;
			}
			uint32_t dst_mask = (uint32_t)0xffffffff >> (32 - sa->address_dst->sadb_address_prefixlen);
			struct sockaddr_in* dst_sockaddr = (struct sockaddr_in*)((uint8_t*)sa->address_dst + sizeof(*sa->address_dst));
			uint32_t d_addr = dst_sockaddr->sin_addr.s_addr;
			if((d_addr & dst_mask) != (ip->destination & dst_mask)) {
				continue;
			}

			rwlock_runlock(&sad->rwlock);
			return sa;
		}
	}

	rwlock_runlock(&sad->rwlock);
	return NULL;
}

SA* sad_get_sa_inbound(SAD* sad, IP* ip) {
	uint32_t spi;
	switch(ip->protocol) {
		case IP_PROTOCOL_ESP:
			;
			ESP* esp = (ESP*)ip->body;
			spi = esp->spi;
			break;
		case IP_PROTOCOL_AH:
			;
			AH* ah = (AH*)ip->body;
			spi = ah->spi;
			break;
		default:
			return NULL;
	}

	rwlock_rlock(&sad->rwlock);
	Map* _sad = map_get(sad->database, (void*)(uint64_t)spi);
	if(!_sad) {
		rwlock_runlock(&sad->rwlock);
		return NULL;
	}

	SA* sa = map_get(_sad, (void*)((uint64_t)ip->destination << 8 | (uint64_t)ip->protocol));
	if(!sa)
		sa = map_get(_sad, (void*)((uint64_t)ip->destination << 8 | 0));

#ifdef DEBUG
	if(!sa)
		sa_dump(sa);
#endif
	rwlock_runlock(&sad->rwlock);

	return sa;
}

bool sad_add_sa(SAD* sad, SA* sa) {
	uint32_t spi = sa->sa->sadb_sa_spi;
	struct sockaddr_in* sockaddr = (struct sockaddr_in*)((uint8_t*)sa->address_dst + sizeof(*sa->address_dst));
	uint32_t dest_address = sockaddr->sin_addr.s_addr;
	uint32_t protocol = sa->address_dst->sadb_address_proto;

	rwlock_wlock(&sad->rwlock);
	Map* _sad = map_get(sad->database, (void*)(uint64_t)spi);
	if(!_sad) {
		//TODO fix here hash function fix
		_sad = map_create(1024, NULL, NULL, __gmalloc_pool);
		if(!_sad) {
			rwlock_wunlock(&sad->rwlock);
			return false;
		}

		if(!map_put(sad->database, (void*)(uint64_t)spi, _sad)) {
			map_destroy(_sad);
			rwlock_wunlock(&sad->rwlock);
			return false;
		}
	}

	if(!map_put(_sad, (void*)((uint64_t)dest_address << 8 | (uint64_t)protocol), sa)) {
		if(map_is_empty(_sad)) {
			map_remove(sad->database, (void*)(uint64_t)spi);
			map_destroy(_sad);
		}
		rwlock_wunlock(&sad->rwlock);
		return false;
	}

#ifdef DEBUG
	sa_dump(sa);
#endif
	rwlock_wunlock(&sad->rwlock);

	return true;
}

SA* sad_remove_sa(SAD* sad, uint32_t spi, uint32_t dest_address, uint8_t protocol) {
	rwlock_wlock(&sad->rwlock);
	Map* _sad = map_get(sad->database, (void*)(uint64_t)spi);
	if(!_sad) {
		rwlock_wunlock(&sad->rwlock);
		return NULL;
	}

	SA* sa = map_remove(_sad, (void*)((uint64_t)dest_address << 8 | (uint64_t)protocol));
	if(!sa) {
		rwlock_wunlock(&sad->rwlock);
		return NULL;
	}

	if(map_is_empty(_sad)) {
		map_remove(sad->database, (void*)(uint64_t)spi);
		map_destroy(_sad);
	}

#ifdef DEBUG
	sa_dump(sa);
#endif
	rwlock_wunlock(&sad->rwlock);

	return sa;
}
