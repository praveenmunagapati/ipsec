#include <stdbool.h>

#include "fp_sadb.h"

static void* fp_sadb;
bool fp_sadb_set(int vmid) {
	//TODO get shared memory;
	fp_sadb = NULL;
	//TODO check initialized.
	return false;
}

bool fp_sadb_add(struct sadb_sa* sa) {
	//TODO vm heath check
	//TODO lock;
	uint64_t key;
	return map_put(fp_sadb->database, sa, key);
}

bool fp_sadb_remove(struct sadb_sa* sa) {
	//TODO vm heath check
	//TODO lock;
	uint64_t key;
	return map_remove(fp_sadb->database, key);
}

bool fp_sadb_update() {
	//TODO vm heath check
	//TODO lock;
	return false;
}
