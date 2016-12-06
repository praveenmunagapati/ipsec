#ifndef __SOCKET_H__
#define __SOCKET_H__
#include <net/nic.h>
#include <stdbool.h>
#include "sp.h"
#include "sa.h"
#include "rwlock.h"

#define	SOCKETS	"net.ipsec.sockets"

typedef struct _Socket{
	SP* sp;
	SA* sa;
	bool fin;
	RWLock rwlock;
	uint32_t lifetime;
} Socket;

bool socket_ginit();
void socket_gdestroy();
Socket* socket_create(NIC* nic, SP* sp, SA* sa);
void socket_delete(NIC* nic, Socket* socket);
bool socket_add(NIC* nic, uint32_t src_ip, uint16_t src_port, uint32_t dest_ip, uint16_t dest_port, Socket* socket);
Socket* socket_remove(NIC* nic, uint32_t src_ip, uint16_t src_port, uint32_t dest_ip, uint16_t dest_port);
Socket* socket_get(NIC* nic, uint32_t src_ip, uint16_t src_port, uint32_t dest_ip, uint16_t dest_port);
bool socket_ref(Socket* socket);
bool socket_unref(Socket* socket);

#endif /*__SOCKET_H__*/
