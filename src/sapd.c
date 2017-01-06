#include <stdint.h>
#include <malloc.h>
#define DONT_MAKE_WRAPPER
#include <_malloc.h>
#undef DONT_MAKE_WRAPPER
#include <string.h>

#include "sapd.h"

#define MAGIC_STRING	"PACKETNGIN_SAPD"

extern void* __gmalloc_pool;
SAPD* sapd_create() {
	SAPD* sapd = __malloc(sizeof(SAPD), __gmalloc_pool);
	memset(sapd, 0, sizeof(SAPD));
	strcpy(sapd->magic, MAGIC_STRING);
	sapd->sad = sad_create();
	sapd->spd = spd_create();

	if(!(sapd->sad && sapd->spd))
		goto fail;

	return sapd;

fail:
	if(sapd->sad)
		sad_delete(sapd->sad);

	if(sapd->spd)
		spd_delete(sapd->spd);

	__free(sapd, __gmalloc_pool);

	return NULL;
}

void sapd_delete(SAPD* sapd) {
	sad_delete(sapd->sad);
	spd_delete(sapd->spd);
	__free(sapd, __gmalloc_pool);
}

bool sapd_check(void* shared_memory) {
	SAPD* sapd = (SAPD*)shared_memory;
	if(!strncmp(sapd->magic, MAGIC_STRING, strlen(MAGIC_STRING)))
		return true;

	return false;
}

bool sapd_add_sa(SAPD* sapd, SA* sa) {
	return sad_add_sa(sapd->sad, sa);
}

SA* sapd_get_sa_inbound(SAPD* sapd, uint32_t spi, uint32_t dest_address, uint8_t protocol) {
	return sad_get_sa_inbound(sapd->sad, spi, dest_address, protocol);
}

SA* sapd_get_sa_outbound(SAPD* sapd, struct sadb_x_ipsecrequest* ipsecrequest, IP* ip) {
	return sad_get_sa_outbound(sapd->sad, ipsecrequest, ip);
}

SA* sapd_remove_sa(SAPD* sapd, uint32_t spi, uint32_t dest_address, uint8_t protocol) {
	return sad_remove_sa(sapd->sad, spi, dest_address, protocol);
}

bool sapd_add_sp(SAPD* sapd, SP* sp) {
	return spd_add_sp(sapd->spd, sp);
}

SP* sapd_get_sp(SAPD* sapd, uint32_t policy, uint32_t src_address, uint32_t dest_address) {
	return spd_get_sp(sapd->spd, policy, src_address, dest_address);
}

SP* sapd_remove_sp(SAPD* sapd, uint32_t policy, uint32_t src_address, uint32_t dest_address) {
	return spd_get_sp(sapd->spd, policy, src_address, dest_address);
}

