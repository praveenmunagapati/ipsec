/*
   * RFC2367 https://www.ietf.org/rfc/rfc2367.txt
   * PF_KEY Key Management API, version 2
 */
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>

#include <sa.h>

#include "sapd.h"
#include "sadb.h"
#include "debug.h"

static bool sadb_get(int fd, uint8_t satype, struct sadb_sa* sa, struct sadb_address* source, struct sadb_address* destination);

static bool sadb_update_process(SAPD* sapd, struct sadb_msg* recv_msg) {
	int len = recv_msg->sadb_msg_len - (sizeof(struct sadb_msg) / 8);
	if(len <= 0)
		return false;

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
				DEBUG_PRINT("Error: sadb_ext_type = %d\n", sadb_ext->sadb_ext_type);
				break;
		}

		if(len < sadb_ext->sadb_ext_len) {
			DEBUG_PRINT("Error: len < sadb_ext->sadb_ext_len\n");
			return false;
		}

		len -= sadb_ext->sadb_ext_len;
		sadb_ext = (struct sadb_ext*)((uint8_t*)sadb_ext + sadb_ext->sadb_ext_len * 8);
	}

	//TODO update sa from shared sadb
	return true;
}

static bool sadb_add_process(int fd, SAPD* sapd, struct sadb_msg* recv_msg) {
	int len = recv_msg->sadb_msg_len - (sizeof(struct sadb_msg) / 8);
	if(len <= 0)
		return false;

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
			case SADB_EXT_KEY_AUTH:
				break;
			case SADB_EXT_KEY_ENCRYPT:
				break;
			case SADB_EXT_IDENTITY_SRC:
			case SADB_EXT_IDENTITY_DST:
			case SADB_EXT_SENSITIVITY:
				break;
			case SADB_X_EXT_SA2:
				break;
			default:
				DEBUG_PRINT("Error: sadb_ext_type = %d\n", sadb_ext->sadb_ext_type);
				break;
		}

		if(len < sadb_ext->sadb_ext_len) {
			DEBUG_PRINT("Error: len < sadb_ext->sadb_ext_len\n");
			return false;
		}
		len -= sadb_ext->sadb_ext_len;
		sadb_ext = (struct sadb_ext*)((uint8_t*)sadb_ext + sadb_ext->sadb_ext_len * 8);
	}

	//TODO SADB Get Request
	if(!!sadb_sa & !!sadb_address_source & !!sadb_address_destination)
		sadb_get(fd, recv_msg->sadb_msg_satype, sadb_sa, sadb_address_source, sadb_address_destination);

	return true;
}

static bool sadb_delete_process(SAPD* sapd, struct sadb_msg* recv_msg) {
	int len = recv_msg->sadb_msg_len - (sizeof(struct sadb_msg) / 8);
	if(len <= 0)
		return false;

	struct sadb_ext* sadb_ext = (struct sadb_ext*)((uint8_t*)recv_msg + sizeof(struct sadb_msg));
	struct sadb_sa* sadb_sa = NULL;
	//struct sadb_address* sadb_address_source = NULL;
	struct sadb_address* sadb_address_destination = NULL;
	while(len) {
		switch(sadb_ext->sadb_ext_type) {
			case SADB_EXT_RESERVED:
				break;
			case SADB_EXT_SA:
				sadb_sa = (struct sadb_sa*)sadb_ext;
				break;
 			case SADB_EXT_ADDRESS_SRC:
// 				sadb_address_source = (struct sadb_address*)sadb_ext;
 				break;
			case SADB_EXT_ADDRESS_DST:
				sadb_address_destination = (struct sadb_address*)sadb_ext;
				break;
			default:
				//DEBUG_PRINT("Error: sadb_ext_type = %d\n", sadb_ext->sadb_ext_type);
				break;
		}

		if(len < sadb_ext->sadb_ext_len) { 
			DEBUG_PRINT("Error: len < sadb_ext->sadb_ext_len\n");
			return false;
		}
		len -= sadb_ext->sadb_ext_len;
		sadb_ext = (struct sadb_ext*)((uint8_t*)sadb_ext + sadb_ext->sadb_ext_len * 8);
	}

	struct sockaddr_in* sockaddr = (struct sockaddr_in*)((uint8_t*)sadb_address_destination + sizeof(*sadb_address_destination));
	uint32_t dest_address = sockaddr->sin_addr.s_addr;
	uint8_t protocol = sadb_address_destination->sadb_address_proto;

	SA* sa = sapd_remove_sa(sapd, sadb_sa->sadb_sa_spi, dest_address, protocol);
	if(sa) {
		sa_free(sa);
		return true;
	}

	return true;
}

static bool sadb_get_process(SAPD* sapd, struct sadb_msg* recv_msg) {
	int len = recv_msg->sadb_msg_len;

	if(len - (sizeof(struct sadb_msg) / 8) <= 0) {
		printf("Wrong Length\n");
		return false;
	}

	SA* sa = sa_alloc(len * 8);
	memcpy(sa->data, (uint8_t*)recv_msg, len * 8);
	sa->sadb_msg = (struct sadb_msg*)(sa->data);
	len -= (sizeof(struct sadb_msg) / 8);

	struct sadb_ext* sadb_ext = (struct sadb_ext*)(sa->data + sizeof(struct sadb_msg));
	while(len) {
		switch(sadb_ext->sadb_ext_type) {
			case SADB_EXT_RESERVED:
				DEBUG_PRINT("reserved %d\n", sadb_ext->sadb_ext_type);
				break;
			case SADB_EXT_SA:
				sa->sa = (struct sadb_sa*)sadb_ext;
				break;
			case SADB_EXT_LIFETIME_CURRENT:
				sa->lifetime_current = (struct sadb_lifetime*)sadb_ext;
				break;
			case SADB_EXT_LIFETIME_HARD:
				sa->lifetime_hard = (struct sadb_lifetime*)sadb_ext;
				break;
			case SADB_EXT_LIFETIME_SOFT:
				sa->lifetime_soft = (struct sadb_lifetime*)sadb_ext;
				break;
			case SADB_EXT_ADDRESS_SRC:
				sa->address_src = (struct sadb_address*)sadb_ext;
				break;
			case SADB_EXT_ADDRESS_DST:
				sa->address_dst = (struct sadb_address*)sadb_ext;
				break;
			case SADB_EXT_ADDRESS_PROXY:
				sa->address_proxy = (struct sadb_address*)sadb_ext;
				break;
			case SADB_EXT_KEY_AUTH:
				sa->key_auth = (struct sadb_key*)sadb_ext;
				break;
			case SADB_EXT_KEY_ENCRYPT:
				sa->key_encrypt = (struct sadb_key*)sadb_ext;
				break;
			case SADB_EXT_IDENTITY_SRC:
				sa->identity_src = (struct sadb_ident*)sadb_ext;
				break;
			case SADB_EXT_IDENTITY_DST:
				sa->identity_dst = (struct sadb_ident*)sadb_ext;
				break;
			case SADB_EXT_SENSITIVITY:
				sa->sensitivity = (struct sadb_sens*)sadb_ext;
				break;
			case SADB_X_EXT_SA2:
				sa->x_sa2 = (struct sadb_x_sa2*)sadb_ext;
				break;
			default:
				DEBUG_PRINT("Error: sadb_ext_type = %d\n", sadb_ext->sadb_ext_type);
				break;
		}

		if(len < sadb_ext->sadb_ext_len) {
			DEBUG_PRINT("Error: len < sadb_ext->sadb_ext_len\n");
			sa_free(sa);
			return false;
		}
		len -= sadb_ext->sadb_ext_len;
		sadb_ext = (struct sadb_ext*)((uint8_t*)sadb_ext + sadb_ext->sadb_ext_len * 8);
	}

	return sapd_add_sa(sapd, sa);
}

static bool sadb_acquire_process(SAPD* sapd, struct sadb_msg* recv_msg) {
	return false;
}

static bool sadb_expire_process(SAPD* sapd, struct sadb_msg* recv_msg) {
	int len = recv_msg->sadb_msg_len - (sizeof(struct sadb_msg) / 8);
	if(len <= 0)
		return false;

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
				DEBUG_PRINT("Error: sadb_ext_type = %d\n", sadb_ext->sadb_ext_type);
				break;
		}

		if(len < sadb_ext->sadb_ext_len) {
			DEBUG_PRINT("Error: len < sadb_ext->sadb_ext_len\n");
			return false;
		}
		len -= sadb_ext->sadb_ext_len;
		sadb_ext = (struct sadb_ext*)((uint8_t*)sadb_ext + sadb_ext->sadb_ext_len * 8);
	}

	//TODO remove sa from sadb

	return true;
}

static bool sadb_flush_process(SAPD* sapd, struct sadb_msg* recv_msg) {
	sad_flush(sapd->sad);
	return true;
}

static bool sadb_dump_process(SAPD* sapd, struct sadb_msg* recv_msg) {
	return sadb_get_process(sapd, recv_msg);
}

static bool sadb_x_spdupdate_process(SAPD* sapd, struct sadb_msg* recv_msg) {
	//TODO fix update
	int len = recv_msg->sadb_msg_len - (sizeof(struct sadb_msg) / 8);
	if(len <= 0)
		return false;

	SP* sp = sp_alloc(len * 8);
	sp->len = len;
	memcpy(sp->data, (uint8_t*)recv_msg + sizeof(struct sadb_msg), len * 8);
	struct sadb_ext* sadb_ext = (struct sadb_ext*)(sp->data);
	while(len) {
		switch(sadb_ext->sadb_ext_type) {
			case SADB_EXT_RESERVED:
				break;
			case SADB_X_EXT_POLICY:
				sp->policy = (struct sadb_x_policy*)sadb_ext;
				break;
			case SADB_EXT_LIFETIME_CURRENT:
				sp->lifetime_current = (struct sadb_lifetime*)sadb_ext;
				break;
			case SADB_EXT_LIFETIME_HARD:
				sp->lifetime_hard = (struct sadb_lifetime*)sadb_ext;
				break;
			case SADB_EXT_LIFETIME_SOFT:
				sp->lifetime_soft = (struct sadb_lifetime*)sadb_ext;
				break;
			case SADB_EXT_ADDRESS_SRC:
				sp->address_src = (struct sadb_address*)sadb_ext;
				break;
			case SADB_EXT_ADDRESS_DST:
				sp->address_dst = (struct sadb_address*)sadb_ext;
				break;
			default:
				DEBUG_PRINT("Error: sadb_ext_type = %d\n", sadb_ext->sadb_ext_type);
				break;
		}

		if(len < sadb_ext->sadb_ext_len) {
			DEBUG_PRINT("Error: len < sadb_ext->sadb_ext_len\n");
			sp_free(sp);
			return false;
		}
		len -= sadb_ext->sadb_ext_len;
		sadb_ext = (struct sadb_ext*)((uint8_t*)sadb_ext + sadb_ext->sadb_ext_len * 8);
	}
	sp_free(sp);
	return true;
}

static bool sadb_x_spdget_process(SAPD* sapd, struct sadb_msg* recv_msg) {
	int len = recv_msg->sadb_msg_len - (sizeof(struct sadb_msg) / 8);
	if(len <= 0)
		return false;

	SP* sp = sp_alloc(len * 8);
	sp->len = len;
	memcpy(sp->data, (uint8_t*)recv_msg + sizeof(struct sadb_msg), len * 8);
	struct sadb_ext* sadb_ext = (struct sadb_ext*)(sp->data);
	while(len) {
		switch(sadb_ext->sadb_ext_type) {
			case SADB_EXT_RESERVED:
				break;
			case SADB_X_EXT_POLICY:
				sp->policy = (struct sadb_x_policy*)sadb_ext;
				break;
			case SADB_EXT_LIFETIME_CURRENT:
				sp->lifetime_current = (struct sadb_lifetime*)sadb_ext;
				break;
			case SADB_EXT_LIFETIME_HARD:
				sp->lifetime_hard = (struct sadb_lifetime*)sadb_ext;
				break;
			case SADB_EXT_LIFETIME_SOFT:
				sp->lifetime_soft = (struct sadb_lifetime*)sadb_ext;
				break;
			case SADB_EXT_ADDRESS_SRC:
				sp->address_src = (struct sadb_address*)sadb_ext;
				break;
			case SADB_EXT_ADDRESS_DST:
				sp->address_dst = (struct sadb_address*)sadb_ext;
				break;
			default:
				DEBUG_PRINT("Error: sadb_ext_type = %d\n", sadb_ext->sadb_ext_type);
				break;
		}

		if(len < sadb_ext->sadb_ext_len) {
			DEBUG_PRINT("Error: len < sadb_ext->sadb_ext_len\n");
			sp_free(sp);
			return false;
		}
		len -= sadb_ext->sadb_ext_len;
		sadb_ext = (struct sadb_ext*)((uint8_t*)sadb_ext + sadb_ext->sadb_ext_len * 8);
	}
	if(!sapd_add_sp(sapd, sp)) {
		sp_free(sp);
		return false;
	}

	return true;
}

static bool sadb_x_spdadd_process(SAPD* sapd, struct sadb_msg* recv_msg) {
	return sadb_x_spdget_process(sapd, recv_msg);
}

static bool sadb_x_spddelete_process(SAPD* sapd, struct sadb_msg* recv_msg) {
	int len = recv_msg->sadb_msg_len - (sizeof(struct sadb_msg) / 8);
	if(len <= 0)
		return false;

	struct sadb_x_policy* policy = NULL;
	struct sadb_address* address_src = NULL; //source
	struct sadb_address* address_dst = NULL; //destination
	struct sadb_ext* sadb_ext = (struct sadb_ext*)((uint8_t*)recv_msg + sizeof(struct sadb_msg));
	while(len) {
		switch(sadb_ext->sadb_ext_type) {
			case SADB_EXT_RESERVED:
				break;
			case SADB_X_EXT_POLICY:
				policy = (struct sadb_x_policy*)sadb_ext;
				break;
			case SADB_EXT_LIFETIME_CURRENT:
			case SADB_EXT_LIFETIME_HARD:
			case SADB_EXT_LIFETIME_SOFT:
				break;
			case SADB_EXT_ADDRESS_SRC:
				address_src = (struct sadb_address*)sadb_ext;
				break;
			case SADB_EXT_ADDRESS_DST:
				address_dst = (struct sadb_address*)sadb_ext;
				break;
			default:
				DEBUG_PRINT("Error: sadb_ext_type = %d\n", sadb_ext->sadb_ext_type);
				break;
		}

		if(len < sadb_ext->sadb_ext_len) {
			DEBUG_PRINT("Error: len < sadb_ext->sadb_ext_len\n");
			return false;
		}
		len -= sadb_ext->sadb_ext_len;
		sadb_ext = (struct sadb_ext*)((uint8_t*)sadb_ext + sadb_ext->sadb_ext_len * 8);
	}

	struct sockaddr_in* src_sockaddr = (struct sockaddr_in*)((uint8_t*)address_src + sizeof(*address_src));
	uint32_t src_address = src_sockaddr->sin_addr.s_addr;
	struct sockaddr_in* dest_sockaddr = (struct sockaddr_in*)((uint8_t*)address_dst + sizeof(*address_dst));
	uint32_t dest_address = dest_sockaddr->sin_addr.s_addr;

	SP* sp = sapd_remove_sp(sapd, policy->sadb_x_policy_type, src_address, dest_address);
	sp_free(sp);

	return true;
}

static bool sadb_x_spddump_process(SAPD* sapd, struct sadb_msg* recv_msg) {
	sadb_x_spdget_process(sapd, recv_msg);
	return true;
}

static bool sadb_x_spdflush_process(SAPD* sapd, struct sadb_msg* recv_msg) {
	spd_flush(sapd->spd);
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

bool sadb_x_spddump(int fd) {
	struct sadb_msg msg;
	memset(&msg, 0, sizeof(struct sadb_msg));
	msg.sadb_msg_version = PF_KEY_V2;
	msg.sadb_msg_type = SADB_X_SPDDUMP;
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

static bool sadb_get(int fd, uint8_t satype, struct sadb_sa* sa, struct sadb_address* source, struct sadb_address* destination) {
	uint8_t buf[256] = {0, };
	//base
	struct sadb_msg* msg = (struct sadb_msg*)buf;
	msg->sadb_msg_version = PF_KEY_V2;
	msg->sadb_msg_type = SADB_GET;
	msg->sadb_msg_satype = satype;
	msg->sadb_msg_len = sizeof(struct sadb_msg) / 8;
	msg->sadb_msg_pid = getpid();
	//sa
	struct sadb_ext* ext = (struct sadb_ext*)((uint8_t*)msg + sizeof(struct sadb_msg));
	memcpy(ext, sa, sa->sadb_sa_len * 8);
	msg->sadb_msg_len += sa->sadb_sa_len;
	//address source
	ext = (struct sadb_ext*)((uint8_t*)ext + ext->sadb_ext_len * 8);
	memcpy(ext, source, source->sadb_address_len * 8);
	msg->sadb_msg_len += ext->sadb_ext_len;
	//address destination
	ext = (struct sadb_ext*)((uint8_t*)ext + ext->sadb_ext_len * 8);
	memcpy(ext, destination, destination->sadb_address_len * 8);
	msg->sadb_msg_len += ext->sadb_ext_len;

	int length = write(fd, msg, msg->sadb_msg_len * 8);  
	if(length != (msg->sadb_msg_len * 8)) {
		printf("Error\n");
		return false;
	}

	return true;
}

bool sadb_process(int fd, SAPD* sapd) {
	uint8_t buf[PFKEY_BUF_SIZE];
	struct sadb_msg* recv_msg = (struct sadb_msg*)buf;
	int length = read(fd, recv_msg, PFKEY_BUF_SIZE);
	if(length < 0) {
		//printf("Error: %s\n");
		DEBUG_PRINT("Error: sadb_process\n");
		return false;
	}
	switch(recv_msg->sadb_msg_type) {
		case SADB_UPDATE:
			//TODO not yet support update
			DEBUG_PRINT("SADB UPDATE\n");
			sadb_update_process(sapd, recv_msg);
			break;
		case SADB_ADD:
			DEBUG_PRINT("SADB ADD\n");
			sadb_add_process(fd, sapd, recv_msg);
			break;
		case SADB_DELETE:
			DEBUG_PRINT("SADB DELETE\n");
			sadb_delete_process(sapd, recv_msg);
			break;
		case SADB_GET:
			DEBUG_PRINT("SADB GET\n");
			sadb_get_process(sapd, recv_msg);
			break;
		case SADB_ACQUIRE:
			DEBUG_PRINT("SADB ACQUIRE\n");
			sadb_acquire_process(sapd, recv_msg);
			break;
		case SADB_EXPIRE:
			DEBUG_PRINT("SADB EXPIRE\n");
			sadb_expire_process(sapd, recv_msg);
			break;
		case SADB_FLUSH:
			DEBUG_PRINT("SADB FLUSH\n");
			sadb_flush_process(sapd, recv_msg);
			break;
		case SADB_DUMP:
			DEBUG_PRINT("SADB DUMP\n");
			sadb_dump_process(sapd, recv_msg);
			break;
		case SADB_X_PROMISC:
			DEBUG_PRINT("SADB_X PROMISC\n");
			break;
		case SADB_X_PCHANGE:
			DEBUG_PRINT("SADB_X PCHANGE\n");
			break;
		case SADB_X_SPDUPDATE:
			DEBUG_PRINT("SADB_X SPD UPDATE\n");
			sadb_x_spdupdate_process(sapd, recv_msg);
			break;
		case SADB_X_SPDADD:
			DEBUG_PRINT("SADB_X SPD ADD\n");
			sadb_x_spdadd_process(sapd, recv_msg);
			break;
		case SADB_X_SPDDELETE:
			DEBUG_PRINT("SADB_X SPD DELETE\n");
			sadb_x_spddelete_process(sapd, recv_msg);
			break;
		case SADB_X_SPDGET:
			DEBUG_PRINT("SADB_X SPD GET\n");
			sadb_x_spdget_process(sapd, recv_msg);
			break;
		case SADB_X_SPDACQUIRE:
			DEBUG_PRINT("SADB_X SPD ACQUIRE\n");
			break;
		case SADB_X_SPDDUMP:
			DEBUG_PRINT("SADB_X SPD DUMP\n");
			sadb_x_spddump_process(sapd, recv_msg);
			break;
		case SADB_X_SPDFLUSH:
			DEBUG_PRINT("SADB_X SPD FLUSH\n");
			sadb_x_spdflush_process(sapd, recv_msg);
			break;
		case SADB_X_SPDSETIDX:
			DEBUG_PRINT("SADB_X SPD SET IDX\n");
			break;
		case SADB_X_SPDEXPIRE:
			DEBUG_PRINT("SADB_X SPD EXPIRE\n");
			break;
		case SADB_X_SPDDELETE2:
			DEBUG_PRINT("SADB_X SPD DELETE2\n");
			break;
		case SADB_X_NAT_T_NEW_MAPPING:
			DEBUG_PRINT("SADB_X NAT T NEW MAPPING\n");
			break;
		case SADB_X_MIGRATE:
			DEBUG_PRINT("SADB_X MIGRATE\n");
			break;
		default:
			DEBUG_PRINT("Error %d\n", recv_msg->sadb_msg_type);
			break;
	}

	return true;
}
