#ifndef __SOCKET_H__
#define __SOCKET_H__
#include <net/ni.h>
#include <stdbool.h>
#include "sp.h"
#include "sa.h"

#define	SOCKETS	"net.ipsec.sockets"

typedef struct _Socket{
	SP* sp;
	SA* sa;
	bool fin;
	uint32_t lifetime;
} Socket;

bool socket_ginit();
Socket* socket_create(NetworkInterface* ni, SP* sp, SA* sa);
void socket_delete(NetworkInterface* ni, Socket* socket);
bool socket_add(NetworkInterface* ni, uint32_t src_ip, uint16_t src_port, uint32_t dest_ip, uint16_t dest_port, Socket* socket);
Socket* socket_remove(NetworkInterface* ni, uint32_t src_ip, uint16_t src_port, uint32_t dest_ip, uint16_t dest_port);
Socket* socket_get(NetworkInterface* ni, uint32_t src_ip, uint16_t src_port, uint32_t dest_ip, uint16_t dest_port);

#endif /*__SOCKET_H__*/