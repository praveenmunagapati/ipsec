#include <net/nic.h>
#include <util/map.h>
#include <malloc.h>
#include <thread.h>
#define DONT_MAKE_WRAPPER
#include <_malloc.h>
#undef DONT_MAKE_WRAPPER

#include "sp.h"
#include "sa.h"
#include "socket.h"
#include "rwlock.h" 
#define MSL	120 * 2

typedef struct _Sockets {
	RWLock rwlock;
	Map* socket_table;
} Sockets;

bool socket_ginit() {
	int id = thread_id();
	if(id != 0)
		return false;

	int count = nic_count();
	for(int i = 0; i < count; i++) {
		NIC* nic = nic_get(i);
		Sockets* sockets = __malloc(sizeof(Sockets), nic->pool);
		if(!sockets) {
			printf("Can't create sockets\n");
			goto fail;
		}
		memset(sockets, 0, sizeof(Sockets));
		rwlock_init(&(sockets->rwlock));

		sockets->socket_table = map_create(16, NULL, NULL, nic->pool);
		if(!sockets->socket_table) {
			printf("Can't create socket table\n");
			__free(sockets, nic->pool);
			goto fail;
		}

		if(!nic_config_put(nic, SOCKETS, sockets)) {
			printf("Can't add sockets\n");
			map_destroy(sockets->socket_table);
			__free(sockets, nic->pool);
			goto fail;
		}
	}

	return true;

fail:
	for(int i = 0; i < count; i++) {
		NIC* nic = nic_get(i);
		Sockets* sockets = nic_config_remove(nic, SOCKETS);
		if(!sockets)
			continue;

		if(sockets->socket_table) {
			map_destroy(sockets->socket_table);
		}

		if(sockets)
			__free(sockets, nic->pool);

	}

	return false;
}

void socket_gdestroy() {
	int id = thread_id();
	if(id != 0)
		return;

	int count = nic_count();
	for(int i = 0; i < count; i++) {
		NIC* nic = nic_get(i);
		Sockets* sockets = nic_config_remove(nic, SOCKETS);
		if(!sockets)
			continue;

		MapIterator iter;
		map_iterator_init(&iter, sockets->socket_table);
		while(map_iterator_has_next(&iter)) {
			MapEntry* entry = map_iterator_next(&iter);
			Socket* socket = entry->data;
			socket_delete(nic, socket);
		}
		map_destroy(sockets->socket_table);

		if(sockets)
			__free(sockets, nic->pool);

	}
}

Socket* socket_create(NIC* nic, SP* sp, SA* sa) {
	Socket* socket = __malloc(sizeof(socket), nic->pool);
	if(!socket)
		return NULL;

	rwlock_init(&socket->rwlock);
	socket->sp = sp;
	socket->sa = sa;
	socket->fin = false;
	socket->lifetime = MSL; //second

	return socket;
}

void socket_delete(NIC* nic, Socket* socket) {
	__free(socket, nic->pool);
}

bool socket_add(NIC* nic, uint32_t src_ip, uint16_t src_port, uint32_t dest_ip, uint16_t dest_port, Socket* socket) {
	Sockets* sockets = nic_config_get(nic, SOCKETS);
	Map* socket_table = sockets->socket_table;

	uint64_t src_key = (uint64_t)src_ip << 32 | (uint64_t)src_port;
	Map* _socket_table = map_get(socket_table, (void*)src_key);
	rwlock_write_lock(&sockets->rwlock);
	if(!_socket_table) {
		_socket_table = map_create(8, NULL, NULL, nic->pool);
		if(!_socket_table) {
			rwlock_write_unlock(&sockets->rwlock);

			return false;
		}

		if(!map_put(socket_table, (void*)src_key, _socket_table)) {
			map_destroy(_socket_table);
			rwlock_write_unlock(&sockets->rwlock);

			return false;
		}
	}

	uint64_t dest_key = (uint64_t)dest_ip << 32 | (uint64_t)dest_port;
	if(!map_put(_socket_table, (void*)dest_key, socket)) {
		if(map_is_empty(_socket_table)) {
			map_destroy(_socket_table);
			map_remove(socket_table, (void*)src_key);
		}
		rwlock_write_unlock(&sockets->rwlock);

		return false;
	}
	rwlock_write_unlock(&sockets->rwlock);

	return true;
}

Socket* socket_remove(NIC* nic, uint32_t src_ip, uint16_t src_port, uint32_t dest_ip, uint16_t dest_port) {
	Sockets* sockets = nic_config_get(nic, SOCKETS);
	Map* socket_table = sockets->socket_table;

	uint64_t src_key = (uint64_t)src_ip << 32 | (uint64_t)src_port;
	Map* _socket_table = map_get(socket_table, (void*)src_key);
	if(!_socket_table) {
			return NULL;
	}

	uint64_t dest_key = (uint64_t)dest_ip << 32 | (uint64_t)dest_port;
	rwlock_write_lock(&sockets->rwlock);
	Socket* socket = map_remove(_socket_table, (void*)dest_key);
	if(!socket) {
		rwlock_write_unlock(&sockets->rwlock);
		return NULL;
	}

	if(map_is_empty(_socket_table)) {
		map_destroy(_socket_table);
		map_remove(socket_table, (void*)src_key);
	}

	rwlock_write_unlock(&sockets->rwlock);

	return socket;
}

Socket* socket_get(NIC* nic, uint32_t src_ip, uint16_t src_port, uint32_t dest_ip, uint16_t dest_port) {
	Sockets* sockets = nic_config_get(nic, SOCKETS);
	Map* socket_table = sockets->socket_table;

	rwlock_read_lock(&sockets->rwlock);
	uint64_t src_key = (uint64_t)src_ip << 32 | (uint64_t)src_port;
	Map* _socket_table = map_get(socket_table, (void*)src_key);
	if(!_socket_table) {
		rwlock_read_unlock(&sockets->rwlock);
		return NULL;
	}

	uint64_t dest_key = (uint64_t)dest_ip << 32 | (uint64_t)dest_port;
	Socket* socket =  map_get(_socket_table, (void*)dest_key);
	socket_ref(socket);
	rwlock_read_unlock(&sockets->rwlock);

	return socket;
}

bool socket_ref(Socket* socket) {
	rwlock_read_lock(&socket->rwlock);
	return true;
}

bool socket_unref(Socket* socket) {
	rwlock_read_unlock(&socket->rwlock);
	return true;
}
