#ifndef __IPSEC_H__
#define __IPSEC_H__

#include <net/packet.h>

bool ipsec_ginit();
void ipsec_gdestroy();
bool ipsec_init();
void ipsec_destroy();

void ipsec_dump();
void ipsec_spddump();
bool ipsec_process(Packet* packet);

#endif /* __IPSEC_H__ */
