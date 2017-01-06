#ifndef __sad_H__
#define __sad_H__
#include <stdint.h>
#include <util/map.h>

#include <net/ip.h>

#include "sa.h"
#include "rwlock.h"

typedef struct _SAD {
	Map* database;
	RWLock rwlock;
}__attribute__ ((packed)) SAD;

SAD* sad_create();
void sad_delete(SAD* sad);
SA* sad_get_sa_inbound(SAD* sad, uint32_t spi, uint32_t dest_address, uint8_t protocol);
SA* sad_get_sa_outbound(SAD* sad, struct sadb_x_ipsecrequest* ipsecrequest, IP* ip);
bool sad_add_sa(SAD* sad, SA* sa);
SA* sad_remove_sa(SAD* sad, uint32_t spi, uint32_t dest_address, uint8_t protocol);
#endif
