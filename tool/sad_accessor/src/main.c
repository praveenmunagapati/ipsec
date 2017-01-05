#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <malloc.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>

#include <control/vmspec.h>
#include <pn_assistant.h>

#include <sadb.h>
#include <debug.h>
#include <sapd.h>


void load_process(int vmid) { 
	if(!pn_assistant_mapping_global_heap(vmid)) {
		return;
	}

	extern void* __gmalloc_pool;
	__gmalloc_pool =  pn_assistant_get_gmalloc_pool(vmid);
	if(!__gmalloc_pool) {
		printf("Can't Get Gmalloc Pool\n");
		goto exit;
	}

	SAPD* sapd = pn_assistant_get_shared(vmid);
	if(!sapd) {
		printf("Can't Get Shared Memory\n");
		goto exit;
	}

	if(!sapd_check((void*)sapd)) {
		printf("Wrong SAPD\n");
		goto exit;
	}

	int sadb_fd = sadb_connect();
	if(sadb_fd < 0) {
		goto exit;
	}

	fd_set input;
	FD_ZERO(&input);
	FD_SET(sadb_fd, &input);
	if(!sadb_dump(sadb_fd))
		goto exit;
	if(!sadb_x_spddump(sadb_fd))
		goto exit;

	printf("Start\n");
	while(1) {
		int status = pn_assistant_get_vm_status(vmid);
		if(status == VM_STATUS_STOP || status == VM_STATUS_INVALID)
			goto exit;

// 		struct timeval time;
// 		fd_set temp_input = input;
// 		time.tv_sec = 0;
// 		time.tv_usec = 1000;
// 
// 		int retval = select(sadb_fd + 1, &temp_input, 0, 0, &time);
// 		if(retval == -1)
// 			break;
// 		else if(retval == 0) {
// 			if(FD_ISSET(sadb_fd, &temp_input)) {
// 				printf("here?\n");
				if(!sadb_process(sadb_fd, sapd))
					break;
// 			}
// 		}
	}

exit:
	printf("SAPD Exit\n");
	return;
}

int main(int argc, char** argv) {
	printf("--------------------------------\n");
	printf("*** PacketNgin SAPD Accessor ***\n");
	printf("--------------------------------\n");

	printf("Load PacketNgin Assistant\n");
	if(!pn_assistant_load()) {
		printf("Can't Load PacketNgin Assistant\n");
		return -2;
	}

	if(argc != 2) {
		printf("sad_accessor [vmid]\n");
		return -1;
	}

	printf("Connecting to PacketNgin Manager...\n");
	int vmid = strtol(argv[1], NULL, 10);

	printf("PacketNgin Virtual Machine: %d\n", vmid);
	pn_assistant_dump_vm(vmid);

	while(1) {
		int stauts = pn_assistant_get_vm_status(vmid);
		switch(stauts) {
			case VM_STATUS_PAUSE:
			case VM_STATUS_START:
				load_process(vmid);
				break;
			case VM_STATUS_STOP:
			case VM_STATUS_INVALID:
				//unload_process(vmid);
				sleep(1);
				break;
		}
		sleep(1);
	}

	return 0;
}
