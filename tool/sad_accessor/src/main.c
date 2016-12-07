#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/pfkeyv2.h>

#include "sadb.h"
#include "debug.h"

int main(int argc, char** argv) {
	int vmid = 0;

	if(sadb_set(vmid)) {
		printf("Can't get shared buffer\n");
		return -1;
	}

	int fd = sadb_connect();
	if(fd < 0) {
		printf("Can't connect SAD\n");
		return -2;
	}

	sadb_dump(fd);
	sadb_process(fd);
	sadb_disconnect(fd);

	return 0;
}
