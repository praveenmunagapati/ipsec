#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <linux/pfkeyv2.h>
#define DONT_MAKE_WRAPPER
#include <_malloc.h>
#undef DONT_MAKE_WRAPPER
#include <thread.h>
#include <readline.h>
#include <net/nic.h>
#include <net/packet.h>
#include <net/ether.h>
#include <net/arp.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <net/checksum.h>
#include <net/udp.h>
#include <net/tcp.h>
#include <net/interface.h>

#include <util/cmd.h>
#include <util/types.h>

#include "sp.h"
#include "crypto.h"
#include "auth.h"
#include "sad.h"
#include "spd.h"
#include "ipsec.h"
#include "rwlock.h"
#include "route.h"

static bool is_continue;

bool ginit(int argc, char** argv) {
	if(!route_ginit())
		return false;

	if(!ipsec_ginit())
		return false;

	cmd_init();

	return true;
}

bool init(int argc, char** argv) {
	if(!ipsec_init()) {
		return false;
	}

	is_continue  = true;

	return true;
}

void destroy() {
	ipsec_destroy();
}

void gdestroy() {
	ipsec_gdestroy();
}

static bool parse_addr(char* argv, uint32_t* address) {
 	char* next = NULL;
 	uint32_t temp;
 
 	for(int i = 0; i < 4; i++, argv++) {
 		temp = strtol(argv, &next, 0);
 		if(temp > 0xff)
 			return false;
 
 		if(next == argv)
 			return false;
 
 		if(i != 3 && *next != '.')
 			return false;
 
 		*address |= (temp & 0xff) << ((3 - i) * 8);
 		argv = next;
 	}
 
 	return true;
}

static NIC* parse_ni(char* argv) {
	if(strncmp(argv, "eth", 3)) {
		return NULL;
	}

	char* next;
	uint16_t index = strtol(argv + 3, &next, 0);
	if(next == argv + 3) {
		return NULL;
	}

	if(*next != '\0' && *next != '@') {
		return NULL;
	}

	return nic_get(index);
}

static int cmd_ip(int argc, char** argv, void(*callback)(char* result, int exit_status)) {
	if(argc == 1) {
		route_ip_dump();
		return 0;
	}

	if(!strcmp("add", argv[1])) {
		if(argc != 4) {
			printf("Wrong arguments\n");
			return -2;
		}
		NIC* ni = parse_ni(argv[2]);
		if(!ni) {
			printf("Netowrk Interface number wrong\n");
			return -2;
		}

		uint32_t addr = 0;
		uint32_t netmask = 0xffffffff;

		if(!parse_addr(argv[3], &addr)) {
			printf("Wrong addr format\n");
			return -3;
		}

		//TODO set netmask
		netmask <<= 8;
		if(!route_ip_add(ni, addr, netmask)) { 
			printf("Fail\n");
			return -4;
		}
	} else if(!strcmp("remove", argv[1])) {
		if(argc != 4) {
			printf("Wrong arguments\n");
			return -2;
		}
		uint32_t addr = 0;
		NIC* ni = parse_ni(argv[2]);
		if(!ni) {
			printf("Netowrk Interface number wrong\n");
			return -2;
		}

		if(!parse_addr(argv[3], &addr)) {
			printf("Wrong addr format\n");
			return -3;
		}

		if(!route_ip_del(ni, addr, 0xffffff00)) {
			printf("Can'nt found address\n");
			return -4;
		}
	} else
		return -1;

	return 0;
}

static int cmd_route(int argc, char** argv, void(*callback)(char* result, int exit_status)) {
	if(argc == 1) {
		route_table_dump();
		return 0;
	}

	uint32_t addr = 0;
	uint32_t mask = 0xffffff00;
	uint32_t gw = 0;
	NIC* dev = NULL;
	if(!strcmp("add", argv[1])) {
		if(!parse_addr(argv[2], &addr))
			return -3;

		for(int i = 3; i < argc; i++) {
			if(!strcmp(argv[i], "gw")) {
				i++;
				if(!parse_addr(argv[i], &gw)) {
					return -i;
				}
			} else if(!strcmp(argv[i], "dev")) {
				i++;
				dev = parse_ni(argv[i]);
				if(!dev) {
					return -i;
				}
			}
		}

		if(!addr | !gw | !dev) {
			printf("Wrong Parameter\n");
			return  -1;
		}

		//TODO fix netmask
		bool result = route_add(addr, mask, gw, dev);
		if(!result) {
			printf("Can't add route\n");
			return -4;
		}
	} else if(!strcmp("del", argv[1])) {
		if(!parse_addr(argv[2], &addr))
			return -3;

		for(int i = 3; i < argc; i++) {
			if(!strcmp(argv[i], "gw")) {
				i++;
				if(!parse_addr(argv[i], &gw)) {
					return -i;
				}
			} else if(!strcmp(argv[i], "dev")) {
				i++;
				dev = parse_ni(argv[i]);
				if(!dev) {
					return -i;
				}
			}
		}

		if(!addr | !gw | !dev) {
			printf("Wrong Parameter\n");
			return  -1;
		}

		if(!route_del(addr, mask, gw, dev)) {
			printf("Wrong\n");
			return -2;
		}
	} else
		return -1;

	return 0;
}
/*
   * SAD Dump
 */
static int cmd_dump(int argc, char** argv, void(*callback)(char* result, int exit_status)) {
	printf("SAD Dump\n");
	ipsec_dump();

	return 0;
}

static int cmd_spddump(int argc, char** argv, void(*callback)(char* result, int exit_status)) {
	printf("SPD Dump\n");
	ipsec_spddump();

	return 0;
}
	
static int cmd_exit(int argc, char** argv, void(*callback)(char* result, int exit_status)) {
	return 0;
}


Command commands[] = {
	{
		.name = "help",
		.desc = "Show This Message",
		.func = cmd_help
	},
	{
		.name = "ip",
		.desc = "add or remove IP",
		.func = cmd_ip
	},
	{
		.name = "route",
		.desc = "add or remove Gateway",
		.func = cmd_route
	},
	{
		.name = "dump",
		.desc = "Dump all SAD Entry",
		.func = cmd_dump
	},
	{
		.name = "spddump",
		.desc = "Dump all SPD Entry",
		.func = cmd_spddump
	},
	{
		.name = "exit",
		.desc = "Exit IPSec Application",
		.func = cmd_exit
	},
	{
		.name = NULL,
		.desc = NULL,
		.func = NULL
	}
};

static bool process(Packet* packet) {
     	if(arp_process(packet))
     		return true;
 
   	if(icmp_process(packet))
   		return true;
 
 	if(ipsec_process(packet))
 		return true;

	return false;
}

int main(int argc, char** argv) {
 	uint16_t id = thread_id();
 	if(id == 0) {
 		ginit(argc, argv);
 	}
 
 	thread_barrior();
 	if(!init(argc, argv)) {
 		return -1;
 	}
 	thread_barrior();
 
 	uint32_t count = nic_count();
 	while(is_continue) {
   		for(int i = 0; i < count; i++) {
   			NIC* nic = nic_get(i);
   			if(nic_has_input(nic)) {
   				Packet* packet = nic_input(nic);
   				if(!packet)
   					continue;
   
   				if(!process(packet)) {
   					nic_free(packet);
   				}
   			}
   		}
  		char* line = readline();
  		if(line != NULL) {
  			if(id == 0) {
  				cmd_exec(line, NULL);
  			}
  		}
 	}
 
 	thread_barrior();
 
 	destroy();
 
 	thread_barrior();
 
 	if(thread_id() == 0) {
 		gdestroy(argc, argv);
 	}

	return 0;
}
