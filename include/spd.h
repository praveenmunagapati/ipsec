#ifndef __spd_H__
#define __spd_H__

#include <stdint.h>
#include <util/list.h>

#include "sp.h"
#include "rwlock.h"

typedef struct _SPD {
	List* list;
	RWLock rwlock;
} SPD;

SPD* spd_create();
bool spd_delete(SPD* spd);
void spd_flush(SPD* spd);

bool spd_add_sp(SPD* spd, SP* sp);
SP* spd_remove_sp(SPD* spd, uint8_t policy, uint32_t src_address, uint32_t dest_address);
SP* spd_get_sp(SPD* spd, uint8_t policy, IP* ip);

#endif /*__SPD_H__*/
