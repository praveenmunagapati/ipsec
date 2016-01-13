#ifndef __AH_H__
#define __AH_H__

#include <util/types.h>

typedef struct _AH{
	uint8_t		next_hdr;
	uint8_t		len;
	uint16_t 	reserved;
	uint32_t 	spi;
	uint32_t 	seq_num;

	uint8_t		auth_data[0]; //icv + payload
} __attribute__ ((packed)) AH;

#endif 
