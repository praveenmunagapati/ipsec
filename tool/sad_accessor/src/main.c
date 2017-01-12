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
	int sadb_fd = 0;

	printf("Mapping Global Heap...");
	if(!pn_assistant_mapping_global_heap(vmid)) {
		printf("Fail\n");
		return;
	}
	printf("OK\n");

	printf("Setting GMalloc Pool...");
	extern void* __gmalloc_pool;
	__gmalloc_pool =  pn_assistant_get_gmalloc_pool(vmid);
	if(!__gmalloc_pool) {
		printf("Fail\n");
		goto exit;
	}
	printf("OK\n");

	printf("Setting SAPD...");
	SAPD* sapd = pn_assistant_get_shared(vmid);
	if(!sapd) {
		printf("Fail\n");
		goto exit;
	}
	printf("OK\n");

	printf("Checking SAPD...");
	if(!sapd_check((void*)sapd)) {
		printf("Fail\n");
		goto exit;
	}
	printf("OK\n");

	printf("Flushing SAPD...\n");
	sapd_flush(sapd);

	printf("Connecting SADB...");
	sadb_fd = sadb_connect();
	if(sadb_fd < 0) {
		printf("Fail\n");
		goto exit;
	}
	printf("OK\n");

	fd_set input;
	FD_ZERO(&input);
	FD_SET(sadb_fd, &input);
	printf("Copying SA Database...");
	if(!sadb_dump(sadb_fd)) {
		printf("Fail\n");
		goto exit;
	}
	printf("OK\n");

	printf("Copying SP Database...");
	if(!sadb_x_spddump(sadb_fd)) {
		printf("Fail\n");
		goto exit;
	}
	printf("OK\n");

	while(1) {
		int status = pn_assistant_get_vm_status(vmid);
		if(status == VM_STATUS_STOP || status == VM_STATUS_INVALID) {
			printf("IPSec is not working\n");
			goto exit;
		}

		struct timeval time;
		fd_set temp_input = input;
		time.tv_sec = 0;
		time.tv_usec = 1000000; // 1 mili second delay

		int retval = select(sadb_fd + 1, &temp_input, 0, 0, &time);
		if(retval == -1) {
			printf("Select Error\n");
			goto exit;
		} else if(retval) {
			if(FD_ISSET(sadb_fd, &temp_input)) {
				if(!sadb_process(sadb_fd, sapd)) {
					printf("SADB Process Error\n");
					goto exit;
				}
			}
		}
	}

exit:
	printf("Unmapping Global Heap...\n");
	if(sadb_fd)
		close(sadb_fd);
	__gmalloc_pool = NULL;
	pn_assistant_unmapping_global_heap();
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
		int status = pn_assistant_get_vm_status(vmid);
		switch(status) {
			case VM_STATUS_PAUSE:
			case VM_STATUS_START:
				load_process(vmid);
				break;
			case VM_STATUS_STOP:
			case VM_STATUS_INVALID:
				break;
		}
		sleep(1);
	}

	return 0;
}
