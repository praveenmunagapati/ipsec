#ifndef __sp_H__
#define __sp_H__

// 
// #include <stdint.h>
// #include <util/list.h>
// #include <net/ip.h>
// #include <net/tcp.h>
// #include <net/udp.h>
// 
// #include "sa.h"

// /* protocol */
// #define IP_PROTOCOL_ANY         0x00
// /* in net/ip.h */
// // #define IP_PROTOCOL_IP          0x04	///< IP protocol number for IP
// // #define IP_PROTOCOL_UDP		0x11	///< IP protocol number for UDP
// // #define IP_PROTOCOL_TCP		0x06	///< IP protocol number for TCP
// #define PORT_ANY		0x00
// 
// /* Direction */
// #define DIRECTION_IN		0x01
// #define DIRECTION_OUT		0x02
// //#define DIRECTION_BI		0x03
// 
// /* Level */
// #define DEFAULT			0x01    
// #define USE			0x02
// #define REQUIRE			0x03
// #define UNIQUE			0x04
// 
// typedef enum {
// 	SP_NONE,
// 	SP_DIRECTION,
// 	SP_IPSEC_ACTION,
// 
// 	SP_PROTOCOL,
// 	SP_IS_PROTOCOL_SA_SHARE,
// 	SP_SOURCE_IP,
// 	SP_IS_SOURCE_IP_SA_SHARE,
// 	SP_SOURCE_NET_MASK,
// 	SP_SOURCE_PORT,
// 	SP_IS_SOURCE_PORT_SA_SHARE,
// 
// 	SP_OUT_NI,
// 	SP_DESTINATION_IP,
// 	SP_IS_DESTINATION_IP_SA_SHARE,
// 	SP_DESTINATION_NET_MASK,
// 	SP_DESTINATION_PORT,
// 	SP_IS_DESTINATION_PORT_SHARE,
// } SP_ATTRIBUTES;
#include <linux/pfkeyv2.h>
#include <sa.h>

typedef struct _SP{
	struct sadb_x_policy* policy;
	struct sadb_lifetime* lifetime_current; //current
	struct sadb_lifetime* lifetime_hard; //hard
	struct sadb_lifetime* lifetime_soft; //soft
	struct sadb_address* address_src; //source
	struct sadb_address* address_dst; //destination
	uint16_t len;
	uint8_t data[0];
} SP;

SP* sp_alloc(int data_size);
bool sp_free(SP* sp);
void sp_dump(SP* sp);

SA* sp_get_sa_cache(SP* sp, IP* ip);
// bool sp_add_content(SP* sp, Content* content, int priority);
// bool sp_remove_content(SP* sp, int index);
// bool sp_add_sa(SP* sp, SA* sa);
// bool sp_remove_sa(SP* sp, SA* sa);
// SA* sp_get_sa(SP* sp, IP* ip);
// SA* sp_find_sa(SP* sp, IP* ip);
// bool sp_verify_sa(SP* sp, List* sa_list, IP* ip);
#endif /* __sp_H__ */
