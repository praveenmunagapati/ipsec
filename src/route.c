#include <stdio.h>
#include <gmalloc.h>

#include <util/list.h>
#include <net/ether.h>
#include <net/arp.h>
#include <net/ip.h>
#include <net/interface.h>
#include <net/checksum.h>

#include "route.h"

/*
   * TODO: Fix Routing mechanism.
   * This api need optimization.
 */
static List* route_table;
typedef struct RouteEntry {
	uint32_t addr;
	uint32_t netmask;
	uint32_t gw;
	uint32_t src; //source
	NIC* dev;
} RouteEntry;

bool route_ginit() {
	extern void* __gmalloc_pool;
	route_table = list_create(__gmalloc_pool);
	if(!route_table)
		return false;

	return true;
}	

void route_gdestroy() {
	//TODO
}

bool route_ip_add(NIC* dev, uint32_t addr, uint32_t netmask) {
	if(!nic_ip_add(dev, addr))
		return false;

	if(!route_add(addr & netmask, netmask, 0, dev)) {
		nic_ip_remove(dev, addr);
		return false;
	}

	return true;
}

bool route_ip_del(NIC* dev, uint32_t addr, uint32_t netmask) {
	if(!route_del(addr & netmask, netmask, 0, dev)) {
		return false;
	}

	if(!nic_ip_remove(dev, addr)) {
		printf("Can'nt found address\n");
		return false;
	}
	//remove all
	return true;
}

bool route_add(uint32_t addr, uint32_t netmask, uint32_t gw, NIC* dev) {
	//TODO check gw unreachable
	if(addr & !netmask) {
		return false;
	}

	uint32_t src;
	Map* interfaces = nic_config_get(dev, NIC_ADDR_IPv4);
	if(!interfaces) {
		return false;
	}

	MapIterator iter;
	map_iterator_init(&iter, interfaces);
	while(map_iterator_has_next(&iter)) {
		MapEntry* entry = map_iterator_next(&iter);
		uint32_t _addr = (uint32_t)(uint64_t)entry->key;
		//IPv4Interface* interface = entry->data;
		if(gw) {
			if((_addr & netmask) == (gw & netmask)) {
				src = _addr;
				goto next;
			}
		} else {
			if((_addr & netmask) == (addr & netmask)) {
				src = _addr;
				goto next;
			}
		}
	}

	return false;
next:
;

	RouteEntry* route_entry = gmalloc(sizeof(RouteEntry));
	if(!route_entry)
		return false;

	route_entry->addr = addr;
	route_entry->netmask = netmask;
	route_entry->gw = gw;
	route_entry->dev = dev;
	route_entry->src = src;

	bool result = list_add(route_table, route_entry);
	if(!result) {
		gfree(route_entry);
		return false;
	}

	return true;
}

bool route_del(uint32_t addr, uint32_t netmask, uint32_t gw, NIC* dev) {
	ListIterator iter;
	list_iterator_init(&iter, route_table);
	while(list_iterator_has_next(&iter)) {
		RouteEntry* route_entry = list_iterator_next(&iter);
		if(route_entry->addr != addr)
			continue;

		if(route_entry->netmask != netmask)
			continue;
		
		if(route_entry->gw != gw)
			continue;
		
		if(route_entry->dev != dev)
			continue;

		list_iterator_remove(&iter);
		gfree(route_entry);
	}

	return false;
}

static void dump_addr(uint32_t addr) {
	printf("%d.%d.%d.%d", (addr >> 24) & 0xff,
			(addr >> 16) & 0xff,
			(addr >> 8) & 0xff,
			addr & 0xff);
}

void route_ip_dump() {
	int count = nic_count();
	printf("** PacketNgin IP Table **\n");
	printf("NIC\tAddress\n");
	for(int i = 0; i < count; i++) {
		NIC* ni = nic_get(i);
		Map* interfaces = nic_config_get(ni, NIC_ADDR_IPv4);
		if(!interfaces) {
			continue;
		}
		MapIterator iter;
		map_iterator_init(&iter, interfaces);
		while(map_iterator_has_next(&iter)) {
			MapEntry* entry = map_iterator_next(&iter);
			printf("eth\t", i);
			dump_addr((uint32_t)(uint64_t)entry->key);
			printf("\n");
		}
	}
}

void route_table_dump() {
	void route_dump(RouteEntry* route_entry) {
		//TODO fix dev name
		dump_addr(route_entry->addr);
		printf("\t");
		dump_addr(route_entry->netmask);
		printf("\t");
		dump_addr(route_entry->gw);
		printf("\t");
		printf("\n");
	}

	printf("** PacketNgin Routing Table **\n");
	printf("Addr\t\tNetmask\t\tGateway\t\tNIC\n");
	ListIterator iter;
	list_iterator_init(&iter, route_table);
	while(list_iterator_has_next(&iter)) {
		RouteEntry* route_entry = list_iterator_next(&iter);
		route_dump(route_entry);
	}
}

bool route_process(Packet* packet) {
 	Ether* ether = (Ether*)(packet->buffer + packet->start);
        IP* ip = (IP*)ether->payload;

	ListIterator iter;
	list_iterator_init(&iter, route_table);
	while(list_iterator_has_next(&iter)) {
		RouteEntry* route_entry = list_iterator_next(&iter);
		if(route_entry->addr == (endian32(ip->destination) & route_entry->netmask)) {
			uint32_t next;
			if(!route_entry->gw) {
				next = endian32(ip->destination);
			} else {
				next = route_entry->gw;
			}

			ether->dmac = endian48(arp_get_mac(route_entry->dev, next, route_entry->src));
			ether->smac = endian48(route_entry->dev->mac);

			ip->ttl--;
			ip->checksum = 0;
			ip->checksum = endian16(checksum(ip, ip->ihl * 4));
			nic_output(route_entry->dev, packet);

			return true;
		}
	}

	return false;
}
