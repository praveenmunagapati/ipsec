#include <net/ni.h>
#include <util/map.h>
#include <malloc.h>
#define DONT_MAKE_WRAPPER
#include <_malloc.h>
#undef DONT_MAKE_WRAPPER

#include "sp.h"
#include "sa.h"
#include "socket.h"
#include "rwlock.h"

typedef struct _Sockets {
	RWLock* rwlock;
	Map* socket_table;
} Sockets;

bool socket_ginit() {
	int count = ni_count();
	for(int i = 0; i < count; i++) {
		NetworkInterface* ni = ni_get(i);
		Sockets* sockets = __malloc(sizeof(Sockets), ni->pool);
		if(!sockets) {
			printf("Can't create sockets\n");
			goto fail;
		}
		memset(sockets, 0, sizeof(Sockets));

		sockets->rwlock = __malloc(sizeof(RWLock), ni->pool);
		if(!sockets->rwlock) {
			printf("Can't allocate sockets lock\n");
			__free(sockets, ni->pool);
			goto fail;
		}

		sockets->socket_table = map_create(16, NULL, NULL, ni->pool);
		if(!sockets->socket_table) {
			printf("Can't create socket table\n");
			__free(sockets->rwlock, ni->pool);
			__free(sockets, ni->pool);
			goto fail;
		}

		if(!ni_config_put(ni, SOCKETS, sockets)) {
			printf("Can't add sockets\n");
			map_destroy(sockets->socket_table);
			__free(sockets->rwlock, ni->pool);
			__free(sockets, ni->pool);
			goto fail;
		}
	}

	return true;

fail:
	for(int i = 0; i < count; i++) {
		NetworkInterface* ni = ni_get(i);
		Sockets* sockets = ni_config_remove(ni, SOCKETS);
		if(!sockets)
			continue;

		if(sockets->socket_table) {
			map_destroy(sockets->socket_table);
		}

		if(sockets->rwlock)
			__free(sockets->rwlock, ni->pool);

		if(sockets)
			__free(sockets, ni->pool);

	}

	return false;
}

Socket* socket_create(NetworkInterface* ni, SP* sp, SA* sa) {
	Socket* socket = __malloc(sizeof(socket), ni->pool);
	if(!socket)
		return NULL;

	socket->sp = sp;
	socket->sa = sa;
	socket->fin = false;
	socket->lifetime = 120 * 2; //second

	return socket;
}

void socket_delete(NetworkInterface* ni, Socket* socket) {
	__free(socket, ni->pool);
}

bool socket_add(NetworkInterface* ni, uint32_t src_ip, uint16_t src_port, uint32_t dest_ip, uint16_t dest_port, Socket* socket) {
	Sockets* sockets = ni_config_get(ni, SOCKETS);
	Map* socket_table = sockets->socket_table;

	uint64_t src_key = (uint64_t)src_ip << 32 | (uint64_t)src_port;
	Map* _socket_table = map_get(socket_table, (void*)src_key);
	rwlock_write_lock(sockets->rwlock);
	if(!_socket_table) {
		_socket_table = map_create(8, NULL, NULL, ni->pool);
		if(!_socket_table) {
			rwlock_write_unlock(sockets->rwlock);

			return false;
		}

		if(!map_put(socket_table, (void*)src_key, _socket_table)) {
			map_destroy(_socket_table);
			rwlock_write_unlock(sockets->rwlock);

			return false;
		}
	}

	uint64_t dest_key = (uint64_t)dest_ip << 32 | (uint64_t)dest_port;
	if(!map_put(_socket_table, (void*)dest_key, socket)) {
		if(map_is_empty(_socket_table)) {
			map_destroy(_socket_table);
			map_remove(socket_table, (void*)src_key);
		}
		rwlock_write_unlock(sockets->rwlock);

		return false;
	}
	rwlock_write_unlock(sockets->rwlock);

	return true;
}

Socket* socket_remove(NetworkInterface* ni, uint32_t src_ip, uint16_t src_port, uint32_t dest_ip, uint16_t dest_port) {
	Sockets* sockets = ni_config_get(ni, SOCKETS);
	Map* socket_table = sockets->socket_table;

	uint64_t src_key = (uint64_t)src_ip << 32 | (uint64_t)src_port;
	Map* _socket_table = map_get(socket_table, (void*)src_key);
	if(!_socket_table) {
			return NULL;
	}

	uint64_t dest_key = (uint64_t)dest_ip << 32 | (uint64_t)dest_port;
	rwlock_write_lock(sockets->rwlock);
	Socket* socket = map_remove(_socket_table, (void*)dest_key);
	if(!socket) {
		rwlock_write_unlock(sockets->rwlock);
		return NULL;
	}

	if(map_is_empty(_socket_table)) {
		map_destroy(_socket_table);
		map_remove(socket_table, (void*)src_key);
	}

	rwlock_write_unlock(sockets->rwlock);

	return socket;
}

Socket* socket_get(NetworkInterface* ni, uint32_t src_ip, uint16_t src_port, uint32_t dest_ip, uint16_t dest_port) {
	Sockets* sockets = ni_config_get(ni, SOCKETS);
	Map* socket_table = sockets->socket_table;

	uint64_t src_key = (uint64_t)src_ip << 32 | (uint64_t)src_port;
	Map* _socket_table = map_get(socket_table, (void*)src_key);
	if(!_socket_table) {
			return NULL;
	}

	uint64_t dest_key = (uint64_t)dest_ip << 32 | (uint64_t)dest_port;
	return map_get(_socket_table, (void*)dest_key);
}
