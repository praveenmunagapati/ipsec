#ifndef __sad_H__
#define __sad_H__

#include <stdbool.h>

#include "sa.h"
#include "rwlock.h"

#define	IPSEC_SAD	"net.ipsec.sad"

typedef struct _SAD {
	Map* database;
	RWLock rwlock;
} SAD;

bool sad_ginit();
void sad_gdestroy();
SAD* sad_get(NIC* nic);
void sad_remove_all(NIC* nic);
SA* sad_get_sa(NIC* nic, uint32_t spi, uint32_t dst_ip, uint8_t protocol);
bool sad_add_sa(NIC* nic, SA* sa);
bool sad_remove_sa(NIC* nic, uint32_t spi, uint32_t dest_ip, uint8_t protocol);

void sad_rlock(NIC* nic);
void sad_un_rlock(NIC* nic); 
void sad_wlock(NIC* nic);
void sad_un_wlock(NIC* nic); 
#endif
