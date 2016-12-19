#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <malloc.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>

#include <sadb.h>
#include <debug.h>
#include <sapd.h>
#include <control/rpc.h>
#include <control/vmspec.h>

#define BUFFER_SIZE 102400

extern void** __shared_memory;
extern void* __gmalloc_pool;
SAPD* sapd;

bool memory_mapping(uint32_t count, void** blocks) {
	//TODO fix here
// 	int fd = open("/dev/mem", O_RDWR | O_SYNC);
// 	if(fd < 0) {
// 		perror("Failed to open memory descriptor\n");
// 		return -1;
// 	}
// 
// 	__shared_memory = blocks[3];
// 	for(int i = 0; i < count; i++) {
// 		mmap();
// 	}
// 
// 	close(fd);

	return true;
}

int vm_status = VM_STATUS_INVALID;
static bool get_memory_blocks_callback(uint32_t count, void** blocks, void* context) {
	printf("Count %d\n", count);
	if(count == 0) {
		vm_status = VM_STATUS_INVALID;
		return true;
	}

	for(int i = 0; i < count; i++) {
		printf("Block[%d]: %p\n", i, blocks[i]);
	}

	if(!memory_mapping(count, blocks)) {
		printf("Can't map memory\n");
		return true;
	}

	printf("Virtual Machine Shared Memory Address: %p\n", __shared_memory);
	if(!sapd_check(*__shared_memory)) {
		printf("Shared Memory has not setted\n");
		return -1;
	}
	sapd = *__shared_memory;

	vm_status = VM_STATUS_STOP;

	return true;
}

static fd_set input;
static int sadb_fd = 0;
static bool get_vm_status_callback(VMStatus status, void* context) {
	switch(vm_status) {
		case VM_STATUS_PAUSE:
		case VM_STATUS_START:
			if(!sadb_fd) {
				sadb_fd = sadb_connect();
				if(sadb_fd < 0) {
					printf("Can't connect SAD\n");
					return -2;
				}
				sadb_dump(sadb_fd);
				sadb_x_spddump(sadb_fd);

				FD_ZERO(&input);
				FD_SET(sadb_fd, &input);
			}
			break;
		case VM_STATUS_STOP:
		case VM_STATUS_INVALID:
			if(sadb_fd) {
				sadb_disconnect(sadb_fd);
				sadb_fd = 0;
				FD_ZERO(&input);
			}
			break;
	}
	vm_status = status;

	return true;
}

static void test() {
	sadb_fd = sadb_connect();
	if(sadb_fd < 0) {
		printf("Can't connect SAD\n");
		return;
	}
	sadb_dump(sadb_fd);
	sadb_x_spddump(sadb_fd);
	void* __gmalloc_pool = malloc(80960);

	extern size_t init_memory_pool(size_t, void *, int);
	init_memory_pool(80960, __gmalloc_pool, 1);
	sapd = sapd_create();
	while(1)
		sadb_process(sadb_fd, sapd);
}

int main(int argc, char** argv) {
	test();
	//TODO fix here
	printf("--------------------------------\n");
	printf("*** PacketNgin SAPD Accessor ***\n");
	printf("--------------------------------\n");
	if(argc != 3) {
		printf("sad_accessor [PORT] [vmid]\n");
		return -1;
	}

	printf("Connecting to PacketNgin Manager...\n");
	RPC* rpc = rpc_open("127.0.0.1", strtol(argv[1], NULL, 10), 5);
	if(!rpc) {
		printf("Can't Connect Manager\n");
		return -2;
	}
	int vmid = strtol(argv[2], NULL, 10);
	printf("Connected to PacketNgin Manager\n");

	printf("PacketNgin Virtual Machine: %d\n", vmid);
	//rpc_vm_get_memory_blocks(rpc, get_memory_blocks_callback, NULL);

	while(1) {
		switch(vm_status) {
			case VM_STATUS_STOP:
				//TODO add sleep
				rpc_status_get(rpc, vmid, get_vm_status_callback, NULL);
				break;
			case VM_STATUS_PAUSE:
			case VM_STATUS_START:;
				struct timeval time;
				fd_set temp_input = input;
				time.tv_sec = 0;
				time.tv_usec = 1000;

				int retval = select(sadb_fd + 1, &temp_input, 0, 0, &time);
				if(retval == -1)
					break;
				else if(retval == 0) {
					if(FD_ISSET(sadb_fd, &temp_input)) {
						if(sadb_process(sadb_fd, sapd))
							break;
					}
				}
				break;
			case VM_STATUS_INVALID:
				//TODO add sleep
				//rpc_vm_get_memory_blocks(rpc, get_memory_blocks_callback, NULL);
				break;
		}

		rpc_loop(rpc);
	}

	return 0;
}
