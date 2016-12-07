#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>

#include "sadb.h"
#include "debug.h"

static bool sadb_update_process(struct sadb_msg* recv_msg) {
	int len = recv_msg->sadb_msg_len - (sizeof(struct sadb_msg) / 8);
	struct sadb_ext* sadb_ext = (struct sadb_ext*)((uint8_t*)recv_msg + sizeof(struct sadb_msg));
	struct sadb_sa* sadb_sa = NULL;
	struct sadb_address* sadb_address_source = NULL;
	struct sadb_address* sadb_address_destination = NULL;

	while(len) {
		switch(sadb_ext->sadb_ext_type) {
			case SADB_EXT_RESERVED:
				break;
			case SADB_EXT_SA:
				sadb_sa = (struct sadb_sa*)sadb_ext;
				break;
			case SADB_EXT_LIFETIME_CURRENT:
			case SADB_EXT_LIFETIME_HARD:
			case SADB_EXT_LIFETIME_SOFT:
				break;
			case SADB_EXT_ADDRESS_SRC:
				sadb_address_source = (struct sadb_address*)sadb_ext;
				break;
			case SADB_EXT_ADDRESS_DST:
				sadb_address_destination = (struct sadb_address*)sadb_ext;
				break;
			case SADB_EXT_ADDRESS_PROXY:
				break;
			case SADB_EXT_IDENTITY_SRC:
			case SADB_EXT_IDENTITY_DST:
				break;
			case SADB_EXT_SENSITIVITY:
				break;
			default:
				DEBUG_PRINT("type: %d\n", sadb_ext->sadb_ext_type);
				break;
		}

		if(len < sadb_ext->sadb_ext_len)
			return false;

		len -= sadb_ext->sadb_ext_len;
		sadb_ext = (struct sadb_ext*)((uint8_t*)sadb_ext + sadb_ext->sadb_ext_len * 8);
	}

	//TODO update sa from shared sadb
	return true;
}

static bool sadb_add_process(struct sadb_msg* recv_msg) {
	int len = recv_msg->sadb_msg_len - (sizeof(struct sadb_msg) / 8);
	struct sadb_ext* sadb_ext = (struct sadb_ext*)((uint8_t*)recv_msg + sizeof(struct sadb_msg));
	struct sadb_sa* sadb_sa = NULL;
	struct sadb_address* sadb_address_source = NULL;
	struct sadb_address* sadb_address_destination = NULL;

	while(len) {
		switch(sadb_ext->sadb_ext_type) {
			case SADB_EXT_RESERVED:
				break;
			case SADB_EXT_SA:
				sadb_sa = (struct sadb_sa*)sadb_ext;
				break;
			case SADB_EXT_LIFETIME_HARD:
			case SADB_EXT_LIFETIME_SOFT:
				break;
			case SADB_EXT_ADDRESS_SRC:
				sadb_address_source = (struct sadb_address*)sadb_ext;
				break;
			case SADB_EXT_ADDRESS_DST:
				sadb_address_destination = (struct sadb_address*)sadb_ext;
				break;
			case SADB_EXT_IDENTITY_SRC:
			case SADB_EXT_IDENTITY_DST:
			case SADB_EXT_SENSITIVITY:
				break;
			default:
				//TODO error
				DEBUG_PRINT("Error\n");
				break;
		}

		if(len < sadb_ext->sadb_ext_len)
			return false;
		len -= sadb_ext->sadb_ext_len;
		sadb_ext = (struct sadb_ext*)((uint8_t*)sadb_ext + sadb_ext->sadb_ext_len * 8);
	}

	//TODO add sa from shared sadb
	return true;
}

static bool sadb_delete_process(struct sadb_msg* recv_msg) {
	int len = recv_msg->sadb_msg_len - (sizeof(struct sadb_msg) / 8);
	struct sadb_ext* sadb_ext = (struct sadb_ext*)((uint8_t*)recv_msg + sizeof(struct sadb_msg));
	struct sadb_sa* sadb_sa = NULL;
	struct sadb_address* sadb_address_source = NULL;
	struct sadb_address* sadb_address_destination = NULL;
	while(len) {
		switch(sadb_ext->sadb_ext_type) {
			case SADB_EXT_RESERVED:
				break;
			case SADB_EXT_SA:
				sadb_sa = (struct sadb_sa*)sadb_ext;
				break;
			case SADB_EXT_ADDRESS_SRC:
				sadb_address_source = (struct sadb_address*)sadb_ext;
				break;
			case SADB_EXT_ADDRESS_DST:
				sadb_address_destination = (struct sadb_address*)sadb_ext;
				break;
			default:
				DEBUG_PRINT("Error\n");
				break;
		}

		if(len < sadb_ext->sadb_ext_len)
			return false;
		len -= sadb_ext->sadb_ext_len;
		sadb_ext = (struct sadb_ext*)((uint8_t*)sadb_ext + sadb_ext->sadb_ext_len * 8);
	}
	//TODO remove sa from shared sadb

	return true;
}

static bool sadb_get_process(struct sadb_msg* recv_msg) {
	int len = recv_msg->sadb_msg_len - (sizeof(struct sadb_msg) / 8);
	struct sadb_ext* sadb_ext = (struct sadb_ext*)((uint8_t*)recv_msg + sizeof(struct sadb_msg));
	while(len) {
		switch(sadb_ext->sadb_ext_type) {
			case SADB_EXT_RESERVED:
				DEBUG_PRINT("reserved %d\n", sadb_ext->sadb_ext_type);
				break;
			case SADB_EXT_SA:
				;
				struct sadb_sa* sadb_sa = (struct sadb_sa*)sadb_ext;
				DEBUG_PRINT("sa %d\n", sadb_sa->sadb_sa_exttype);
				break;
			case SADB_EXT_LIFETIME_CURRENT:
			case SADB_EXT_LIFETIME_HARD:
			case SADB_EXT_LIFETIME_SOFT:
				;
				struct sadb_lifetime* sadb_lifetime = (struct sadb_lifetime*)sadb_ext;
				DEBUG_PRINT("lifetime %d\n", sadb_lifetime->sadb_lifetime_exttype);
				break;
			case SADB_EXT_ADDRESS_SRC:
			case SADB_EXT_ADDRESS_DST:
			case SADB_EXT_ADDRESS_PROXY:
				;
				struct sadb_address* sadb_address = (struct sadb_address*)sadb_ext;
				DEBUG_PRINT("address %d\n", sadb_address->sadb_address_exttype);
				DEBUG_PRINT("%d\n", sadb_address->sadb_address_len);
				struct sockaddr_in* sockaddr_in = (struct sockaddr_in*)((uint8_t*)sadb_address + sizeof(struct sadb_address));
				DEBUG_PRINT("%x\n", sockaddr_in->sin_addr.s_addr);
				DEBUG_PRINT("%d\n", sockaddr_in->sin_port);
				 
				break;
			case SADB_EXT_KEY_AUTH:
			case SADB_EXT_KEY_ENCRYPT:
				;
				struct sadb_key* sadb_key = (struct sadb_key*)sadb_ext;
				DEBUG_PRINT("key %d\n", sadb_key->sadb_key_exttype);
				break;
			case SADB_EXT_IDENTITY_SRC:
			case SADB_EXT_IDENTITY_DST:
				;
				struct sadb_ident* sadb_ident = (struct sadb_ident*)sadb_ext;
				DEBUG_PRINT("ident %d\n", sadb_ident->sadb_ident_exttype);
				break;
			case SADB_EXT_SENSITIVITY:
				;
				struct sadb_sens* sadb_sens = (struct sadb_sens*)sadb_ext;
				DEBUG_PRINT("sens %d\n", sadb_sens->sadb_sens_exttype);
				break;
			default:
				DEBUG_PRINT("Error\n");
				break;
		}

		if(len < sadb_ext->sadb_ext_len)
			return false;
		len -= sadb_ext->sadb_ext_len;
		sadb_ext = (struct sadb_ext*)((uint8_t*)sadb_ext + sadb_ext->sadb_ext_len * 8);
	}

	return true;
}

static bool sadb_expire_process(struct sadb_msg* recv_msg) {
	int len = recv_msg->sadb_msg_len - (sizeof(struct sadb_msg) / 8);
	struct sadb_ext* sadb_ext = (struct sadb_ext*)((uint8_t*)recv_msg + sizeof(struct sadb_msg));
	struct sadb_sa* sadb_sa = NULL;
	struct sadb_address* sadb_address_source = NULL;
	struct sadb_address* sadb_address_destination = NULL;
	while(len) {
		switch(sadb_ext->sadb_ext_type) {
			case SADB_EXT_RESERVED:
				break;
			case SADB_EXT_SA:
				sadb_sa = (struct sadb_sa*)sadb_ext;
				break;
			case SADB_EXT_LIFETIME_CURRENT:
			case SADB_EXT_LIFETIME_HARD:
			case SADB_EXT_LIFETIME_SOFT:
				break;
			case SADB_EXT_ADDRESS_SRC:
				sadb_address_source = (struct sadb_address*)sadb_ext;
				break;
			case SADB_EXT_ADDRESS_DST:
				sadb_address_destination = (struct sadb_address*)sadb_ext;
				break;
			default:
				DEBUG_PRINT("Error\n");
				break;
		}

		if(len < sadb_ext->sadb_ext_len)
			return false;
		len -= sadb_ext->sadb_ext_len;
		sadb_ext = (struct sadb_ext*)((uint8_t*)sadb_ext + sadb_ext->sadb_ext_len * 8);
	}

	//TODO remove sa from sadb

	return true;
}

static bool sadb_flush_process(struct sadb_msg* recv_msg) {
	DEBUG_PRINT("flush\n");

	return true;
}

static bool sadb_dump_process(struct sadb_msg* recv_msg) {
	return sadb_get_process(recv_msg);
}

bool sadb_set(int vmid) {
	return true;
}

#define PFKEY_BUF_SIZE		4096
int sadb_connect() {
	int fd = socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
	if(fd < 0) {
		printf("Fail\n");
		return -1;  
	}

	return fd;
}

bool sadb_dump(int fd) {
	struct sadb_msg msg;
	memset(&msg, 0, sizeof(struct sadb_msg));
	msg.sadb_msg_version = PF_KEY_V2;
	msg.sadb_msg_type = SADB_DUMP;
	msg.sadb_msg_satype = 0;
	msg.sadb_msg_len = sizeof(msg) / 8;
	msg.sadb_msg_pid = getpid();

	int length = write(fd, &msg, sizeof(struct sadb_msg));  
	if(length != sizeof(struct sadb_msg)) {
		printf("Error\n");
		return false;
	}
	return true;
}

void sadb_disconnect(int fd) {
	close(fd);
}

bool sadb_get(int fd, struct sadb_sa* sa, struct sadb_address* source, struct sadb_address* destination) {
	uint8_t buf[256] = {0, };
	//base
	struct sadb_msg* msg = (struct sadb_msg*)buf;
	msg->sadb_msg_version = PF_KEY_V2;
	msg->sadb_msg_type = SADB_GET;
	msg->sadb_msg_satype = 0;
	msg->sadb_msg_len = sizeof(msg) / 8;
	msg->sadb_msg_pid = getpid();
	//sa
	struct sadb_ext* ext = (struct sadb_ext*)((uint8_t*)msg + sizeof(struct sadb_msg));
	memcpy(ext, sa, sa->sadb_sa_len * 8);
	msg->sadb_msg_len += sa->sadb_sa_len;
	//address source
	ext = (struct sadb_ext*)((uint8_t*)ext + ext->sadb_ext_len * 8);
	memcpy(ext, source, source->sadb_address_len * 8);
	msg->sadb_msg_len += source->sadb_address_len;
	//address destination
	ext = (struct sadb_ext*)((uint8_t*)ext + ext->sadb_ext_len * 8);
	memcpy(ext, destination, destination->sadb_address_len * 8);
	msg->sadb_msg_len += destination->sadb_address_len;

	int length = write(fd, msg, msg->sadb_msg_len * 8);  
	if(length != (msg->sadb_msg_len * 8)) {
		printf("Error\n");
		return false;
	}

	return true;
}

int sadb_process(int fd) {
	uint8_t* buf[PFKEY_BUF_SIZE];
	struct sadb_msg* recv_msg = (struct sadb_msg*)buf;
	while(1) {
		int length = read(fd, recv_msg, PFKEY_BUF_SIZE);
		if(length < 0) {
			printf("Error\n");
			return -3;
		}
		switch(recv_msg->sadb_msg_type) {
			case SADB_UPDATE:
				sadb_update_process(recv_msg);
				break;
			case SADB_ADD:
				sadb_add_process(recv_msg);
				break;
			case SADB_DELETE:
				sadb_delete_process(recv_msg);
				break;
			case SADB_GET:
				sadb_get_process(recv_msg);
				break;
			case SADB_EXPIRE:
				sadb_expire_process(recv_msg);
				break;
			case SADB_FLUSH:
				sadb_flush_process(recv_msg);
				break;
			case SADB_DUMP:
				sadb_dump_process(recv_msg);
				break;
			default:
				DEBUG_PRINT("Error %d\n", recv_msg->sadb_msg_type);
				break;
		}
	}

	return 0;
}
