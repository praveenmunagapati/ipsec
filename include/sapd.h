#ifndef __SAPD_H__
#define __SAPD_H__

#include "sad.h"
#include "spd.h"
#include <net/ip.h>

/**
  * Security Association & Policy Database
  **/

typedef struct _SAPD {
	char magic[16];
	SAD* sad;
	SPD* spd;
}__attribute__ ((packed)) SAPD;

SAPD* sapd_create();
void sapd_delete();
void sapd_flush(SAPD* sapd);
bool sapd_check(void* shared_memory);

bool sapd_add_sa(SAPD* sapd, SA* sa);
SA* sapd_get_sa_inbound(SAPD* sapd, IP* ip);
SA* sapd_get_sa_outbound(SAPD* sapd, struct sadb_x_ipsecrequest* ipsecrequest, IP* ip);
SA* sapd_remove_sa(SAPD* sapd, uint32_t spi, uint32_t dest_address, uint8_t protocol);

bool sapd_add_sp(SAPD* sapd, SP* sp);
SP* sapd_get_sp(SAPD* sapd, uint32_t policy, IP* ip);
SP* sapd_remove_sp(SAPD* sapd, uint32_t policy, uint32_t src_address, uint32_t dest_address);
#endif /*__SAPD_H__*/
