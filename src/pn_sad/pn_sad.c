#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <malloc.h>
#include <thread.h>
#define DONT_MAKE_WRAPPER
#include <_malloc.h>
#undef DONT_MAKE_WRAPPER
#include <net/nic.h>
#include <net/ip.h>
#include <net/ether.h>
#include <openssl/des.h>
#include <util/map.h>

#include "ipsec.h"
#include "sad.h"
#include "sa.h"
#include "rwlock.h"

// KEY : Packet's dest_ip, ipsec_protocol, spi   
SAD** sads = NULL;
extern void* __gmalloc_pool;

static bool sad_init() {
	int count = nic_count();

	sads = __malloc(sizeof(SAD*) * count, __gmalloc_pool);
	if(!sads)
		return false;

	for(int i = 0; i < count; i++) {
		NIC* nic = nic_get(i);
		SAD* sad = __malloc(sizeof(SAD), __gmalloc_pool);
		if(!sad) {
			goto fail;
		}

		sad->database = map_create(16, NULL, NULL, __gmalloc_pool);
		if(!sad->database) {
			__free(sad, nic->pool);

			goto fail;
		}
		rwlock_init(&sad->rwlock);

		sads[i] = sad;
	}

	return true;

fail:
	for(int nic_index = 0; nic_index < count; nic_index++) {
		SAD* sad = sads[nic_index];
		if(!sad) {
			continue;
		}

		map_destroy(sad->database);
		__free(sad, __gmalloc_pool);
	}

	return false;
}

static void sad_destroy() {
	int count = nic_count();

	for(int nic_index = 0; nic_index < count; nic_index++) {
		SAD* sad = sads[nic_index];
		
		MapIterator iter;
		map_iterator_init(&iter, sad->database);
		while(map_iterator_has_next(&iter)) {
			MapEntry* _entry = map_iterator_next(&_iter);
			SA* sa = _entry->data;
			sa_free(sa);
			map_iterator_remove(&_iter);
		}
		map_destroy(sad->database);
		__free(sad, __gmalloc_pool);
	}
}

static void sad_flush(void) {
	int count = nic_count();

	for(int nic_index = 0; nic_index < count; nic_index++) {
		SAD* sad = sads[nic_index];
		
		MapIterator iter;
		map_iterator_init(&iter, sad->database);
		while(map_iterator_has_next(&iter)) {
			MapEntry* _entry = map_iterator_next(&_iter);
			SA* sa = _entry->data;
			sa_free(sa);
			map_iterator_remove(&_iter);
		}
	}
}

static SA* sad_get_sa(int nic_index, uint32_t spi, uint32_t dest_ip, uint8_t protocol) {
	SAD* sad = sads[nic_index];

	uint64_t key = ((uint64_t)protocol << 32) | (uint64_t)spi;
	List* dest_list = map_get(sad->database, (void*)key);
	if(!dest_list) {
		return NULL;
	}

	bool compare(void* data, void* context) {
		uint32_t dest_addr = (uint32_t)(uint64_t)data;
		SA* sa = context;

		if(sa->ipsec_mode == IPSEC_MODE_TUNNEL) {
			if(dest_addr == sa->t_dest_ip) { 
				return true;
			}
		} else {
			if((dest_addr & sa->dest_mask) == (sa->dest_ip & sa->dest_mask)) {
				return true;
			}
		}

		return false;
	}

	int index = list_index_of(dest_list, (void*)(uint64_t)dest_ip, compare);
	SA* sa = (SA*)list_get(dest_list, index);
	if(!sa) {
		return NULL;
	}

	return sa;
}

static bool sad_add_sa(int nic_index, SA* sa) {
	SAD* sad = sads[nic_index];

	uint64_t key = ((uint64_t)sa->ipsec_protocol << 32) | (uint64_t)sa->spi; /* Protocol(8) + SPI(32)*/

	List* dest_list = map_get(sad->database, (void*)key);
	if(!dest_list) {
		dest_list = list_create(nic->pool);
		if(!dest_list) {
			//printf("Can't create list\n");
			goto protocol_map_create_fail;
		}
		if(!map_put(sad->database, (void*)key, dest_list)) {
			//printf("Can't put list\n");
			goto protocol_map_put_fail;
		}
	}

	if(!list_add(dest_list, (void*)(uint64_t)sa)) {
		//printf("Can't add SA\n");
		goto sa_put_fail;
	}

	return true;

sa_put_fail:
protocol_map_put_fail:
	if(list_is_empty(dest_list)) {
		list_destroy(dest_list);
		map_remove(sad->database, (void*)key);
	}

protocol_map_create_fail:

	return false;
}

bool sad_remove_sa(int nic_index, uint32_t spi, uint32_t dest_ip, uint8_t ipsec_protocol) {
	SAD* sad = sads[nic_index];

	uint64_t key = ((uint64_t)ipsec_protocol << 32) | (uint64_t)spi; /* Protocol(8) + SPI(32)*/

	List* dest_list = map_get(sad->database, (void*)(uint64_t)key);
	if(!dest_list) { 
		printf("Can'nt found SA List\n");

		return false;
	}

	bool compare(void* context, void* data) {
		uint32_t dest_addr = (uint32_t)(uint64_t)context;
		SA* sa = data;

		if((dest_addr & sa->dest_mask) == (sa->dest_ip & sa->dest_mask)) {
			return true;
		}

		return false;
	}

	int index = list_index_of(dest_list, (void*)(uint64_t)dest_ip, compare);
	SA* sa = (SA*)list_remove(dest_list, index);
	if(!sa) { 
		printf("Can'nt found SA\n");
		return false;
	}

	if(list_is_empty(dest_list)) {
		list_destroy(dest_list);
		map_remove(sad->database, (void*)key);
	}

	return sa_free(sa);
}

/* SAD Read & Write Lock */
inline void sad_rlock(int nic_index) {
	SAD* sad = sads[nic_index];
	rwlock_read_lock(&sad->rwlock);
}

inline void sad_un_rlock(int nic_index) {
	SAD* sad = sads[nic_index];
	rwlock_read_unlock(&sad->rwlock);
}

inline void sad_wlock(int nic_index) {
	SAD* sad = sads[nic_index];
	rwlock_write_lock(&sad->rwlock);
}

inline void sad_un_wlock(int nic_index) {
	SAD* sad = sads[nic_index];
	rwlock_write_unlock(&sad->rwlock);
}
