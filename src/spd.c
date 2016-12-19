#include <stdio.h>
#include <malloc.h>
#define DONT_MAKE_WRAPPER
#include <_malloc.h>
#undef DONT_MAKE_WRAPPER
#include <string.h>
#include <netinet/in.h>
#include "spd.h"

extern void* __gmalloc_pool;
SPD* spd_create() {
	SPD* spd = __malloc(sizeof(SPD), __gmalloc_pool);
	if(!spd)
		return NULL;

	memset(spd, 0, sizeof(SPD));
	spd->list = list_create(__gmalloc_pool);
	if(!spd->list)
		goto fail;

	rwlock_init(&spd->rwlock);

	return spd;

fail:
	if(spd->list)
		list_destroy(spd->list);

	__free(spd, __gmalloc_pool);

	return NULL;
}

bool spd_delete(SPD* spd) {
	rwlock_wlock(&spd->rwlock);
	//TODO gabage collection;

	list_destroy(spd->list);

	__free(spd, __gmalloc_pool);

	return true;
}

bool spd_add_sp(SPD* spd, SP* sp) {
	if(!sp->policy || !sp->address_src || !sp->address_dst)
		return false;

	bool compare(void* new_data, void* data) {
		SP* new_sp = new_data;
		SP* sp = data;
		if(new_sp->policy->sadb_x_policy_priority >= sp->policy->sadb_x_policy_priority) {
			return true;
		}
		return false;
	}

	int idx = list_index_of(spd->list, sp, compare);

	if(DEBUG)
		sp_dump(sp);

	return list_add_at(spd->list, idx, sp);
}

SP* spd_remove_sp(SPD* spd, uint8_t policy, uint32_t src_address, uint32_t dst_address) {
	ListIterator iter;
	list_iterator_init(&iter, spd->list);
	while(list_iterator_has_next(&iter)) {
		SP* sp = list_iterator_next(&iter);
		//TODO fix here check mask
		struct sockaddr_in* src_sockaddr = (struct sockaddr_in*)((uint8_t*)sp->address_src + sizeof(*sp->address_src));
		struct sockaddr_in* dst_sockaddr = (struct sockaddr_in*)((uint8_t*)sp->address_dst + sizeof(*sp->address_dst));
		if((src_address == src_sockaddr->sin_addr.s_addr) && (dst_address == dst_sockaddr->sin_addr.s_addr)) {
			list_iterator_remove(&iter);
			if(DEBUG)
				sp_dump(sp);
			return sp;
		}
	}

	return NULL;
}

SP* spd_get_sp(SPD* spd, uint8_t policy, uint32_t src_address, uint32_t dst_address) {
	ListIterator iter;
	list_iterator_init(&iter, spd->list);
	while(list_iterator_has_next(&iter)) {
		SP* sp = list_iterator_next(&iter);
		//TODO fix here check mask
		struct sockaddr_in* src_sockaddr = (struct sockaddr_in*)((uint8_t*)sp->address_src + sizeof(*sp->address_src));
		struct sockaddr_in* dst_sockaddr = (struct sockaddr_in*)((uint8_t*)sp->address_dst + sizeof(*sp->address_dst));
		if((src_address == src_sockaddr->sin_addr.s_addr) && (dst_address == dst_sockaddr->sin_addr.s_addr)) {
			if(DEBUG)
				sp_dump(sp);
			return sp;
		}
	}
	return NULL;
}
