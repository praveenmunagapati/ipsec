#ifndef __spd_H__
#define __spd_H__

#include <stdbool.h>
#include <net/nic.h>
#include "sp.h"
#include "rwlock.h"

#define IPSEC_SPD	"net.ipsec.spd"

typedef struct _SPD {
	List* out_database;
	RWLock out_rwlock;
	List* in_database;
	RWLock in_rwlock;
} SPD;

bool spd_ginit();
void spd_gdestroy();
SPD* spd_get(NIC* nic);
SP* spd_get_sp(NIC* nic, uint8_t direction, IP* ip);
SP* spd_get_sp_index(NIC* nic, uint8_t direction, uint16_t index);
bool spd_add_sp(NIC* nic, uint8_t direction, SP* sp, int priority);
bool spd_remove_sp(NIC* nic, uint8_t direction, int index);
void spd_delete_all(NIC* nic, uint8_t direction);

void spd_inbound_rlock(NIC* nic);
void spd_inbound_un_rlock(NIC* nic); 
void spd_inbound_wlock(NIC* nic);
void spd_inbound_un_wlock(NIC* nic); 
void spd_outbound_rlock(NIC* nic);
void spd_outbound_un_rlock(NIC* nic);
void spd_outbound_wlock(NIC* nic);
void spd_outbound_un_wlock(NIC* nic);
#endif
