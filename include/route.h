#ifndef __ROUTE_H__
#define __ROUTE_H__
#include <net/nic.h>
#include <net/packet.h>

bool route_ginit();
void route_gdestroy();
void route_table_dump();

void route_ip_dump();
bool route_ip_add(NIC* dev, uint32_t addr, uint32_t netmask);
bool route_ip_del(NIC* dev, uint32_t addr, uint32_t netmask);

bool route_add(uint32_t addr, uint32_t netmask, uint32_t gw, NIC* dev);
bool route_del(uint32_t addr, uint32_t netmask, uint32_t gw, NIC* dev);
bool route_process(Packet* packet);

#endif /*__ROUTE_H__*/
