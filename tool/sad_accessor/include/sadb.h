#ifndef __SADB_H__
#define __SADB_H__
#include <linux/pfkeyv2.h>

#include <sapd.h>
int sadb_connect();
void sadb_disconnect(int fd);
int sadb_process(int fd, SAPD* sapd);

bool sadb_dump(int fd);
bool sadb_x_spddump(int fd);
bool sadb_get(int fd, struct sadb_sa* sa, struct sadb_address* source, struct sadb_address* destination);

#endif /*__SADB_H__*/
