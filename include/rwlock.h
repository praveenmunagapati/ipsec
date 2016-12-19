#ifndef ___LOCK_H__
#define ___LOCK_H__

#include <stdint.h>
#include <stdbool.h>

typedef struct _RWLock {
	uint8_t volatile write_lock;
	uint8_t volatile read_lock;

	uint8_t volatile read_count_lock;
	uint8_t volatile read_count;
} RWLock;

/**
 * @file
 * Locking between threads.
 */

/**
 * Initialize the lock object.
 *
 * @param lock lock object
 */
void rwlock_init(RWLock* rwlock);

void rwlock_wlock(RWLock* rwlock);
bool rwlock_wtry_lock(RWLock* rwlock);
void rwlock_wunlock(RWLock* rwlock);

void rwlock_rlock(RWLock* rwlock);
bool rwlock_rtry_lock(RWLock* rwlock);
void rwlock_runlock(RWLock* rwlock);

#endif /* ___LOCK_H__ */
