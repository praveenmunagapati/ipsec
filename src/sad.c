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

#include "sad.h"

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

SA* sad_get_sa_ip(SAD* sad, IP* ip) {
	rwlock_rlock(&sad->rwlock);
	MapIterator iter;
	map_iterator_init(&iter, sad->database);
	while(map_iterator_has_next(&iter)) {
		MapEntry* entry = map_iterator_next(&iter);
		Map* _sad = entry->data;

		MapIterator iter2;
		map_iterator_init(&iter2, _sad);
		while(map_iterator_has_next(&iter2)) {
			MapEntry* entry2 = map_iterator_next(&iter);
			SA* sa = entry2->data;

			struct sockaddr_in* src_sockaddr = (struct sockaddr_in*)((uint8_t*)sa->address_src + sizeof(*sa->address_src));
			struct sockaddr_in* dst_sockaddr = (struct sockaddr_in*)((uint8_t*)sa->address_dst + sizeof(*sa->address_dst));
			//TODO fix here
			if(src_sockaddr->sin_addr.s_addr == endian32(ip->source) && 
					dst_sockaddr->sin_addr.s_addr == endian32(ip->destination)) {
				return sa;
			}
		}
	}

	return NULL;
}

SA* sad_get_sa(SAD* sad, uint32_t spi, uint32_t dest_address, uint8_t protocol) {
	rwlock_rlock(&sad->rwlock);
	Map* _sad = map_get(sad->database, (void*)(uint64_t)spi);
	if(!_sad) {
		return NULL;
	}

	SA* sa = map_get(_sad, (void*)((uint64_t)dest_address << 8 | (uint64_t)protocol));
	rwlock_runlock(&sad->rwlock);
	if(DEBUG)
		sa_dump(sa);

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
	rwlock_wunlock(&sad->rwlock);
	if(DEBUG)
		sa_dump(sa);

	return true;
}

SA* sad_remove_sa(SAD* sad, uint32_t spi, uint32_t dest_address, uint8_t protocol) {
	rwlock_wlock(&sad->rwlock);
	Map* _sad = map_get(sad->database, (void*)(uint64_t)spi);
	if(!_sad) {
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

	rwlock_wunlock(&sad->rwlock);
	if(DEBUG)
		sa_dump(sa);

	return sa;
}
