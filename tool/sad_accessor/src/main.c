#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <malloc.h>

#include "sadb.h"
#include "debug.h"
#include "sapd.h"

#define BUFFER_SIZE 102400
void* get_shared_memory(int vmid) {
	//TODO
	return sapd_create();
}
void dummy_init() {
	extern void* __gmalloc_pool;
	extern size_t init_memory_pool(size_t, void *, int);
	void* buffer = malloc(BUFFER_SIZE);
 	printf("buffer:%p\n", buffer);
	init_memory_pool(BUFFER_SIZE, (void*)buffer, 0);
	__gmalloc_pool = buffer;
}

int main(int argc, char** argv) {
	//TODO fix here
	dummy_init();

	printf("--------------------------------\n");
	printf("*** PacketNgin SAPD Accessor ***\n");
	printf("--------------------------------\n");
	if(argc != 2) {
		printf("Virtual Machine ID is null\n");
		printf("./sad_accessor [vmid]\n");
		return -1;
	}

	int vmid = strtol(argv[1], NULL, 10);
	printf("PacketNgin Virtual Machine: %d\n", vmid);

	while(1) {
		//TODO check machine state
		void* shared_memory = get_shared_memory(vmid);
		if(!shared_memory)
			continue;

		printf("Virtual Machine Shared Memory Address: %p\n", shared_memory);
		if(!sapd_check(shared_memory)) {
			printf("Shared Memory has not setted\n");
			return -1;
		}
		SAPD* sapd = shared_memory;
		int fd = sadb_connect();
		if(fd < 0) {
			printf("Can't connect SAD\n");
			return -2;
		}
		sadb_dump(fd);
		sadb_x_spddump(fd);
		while(1) {
			// TODO select 
			// TODO check machine state
			if(sadb_process(fd, sapd))
				break;
		}
		sadb_disconnect(fd);
	}

	return 0;
}
