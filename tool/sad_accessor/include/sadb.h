#ifndef __SADB_H__
#define __SADB_H__
#include <linux/pfkeyv2.h>

#include <sapd.h>
int sadb_connect();
void sadb_disconnect(int fd);
bool sadb_process(int fd, SAPD* sapd);

bool sadb_dump(int fd);
bool sadb_x_spddump(int fd);

#endif /*__SADB_H__*/
