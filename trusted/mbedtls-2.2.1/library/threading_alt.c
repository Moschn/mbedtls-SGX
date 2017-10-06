#include "mbedtls/threading_alt.h"
#include <stdlib.h>

void threading_mutex_init_sgx(mbedtls_threading_mutex_t *mutex)
{
    if (mutex == NULL) return;
    sgx_thread_mutexattr_t unused;
    if (mutex->mutex == NULL) mutex->mutex = malloc(sizeof(sgx_thread_mutex_t));
    mutex->is_valid = sgx_thread_mutex_init(mutex->mutex, &unused);
}

void threading_mutex_free_sgx(mbedtls_threading_mutex_t *mutex)
{
    if (mutex == NULL) return;
    sgx_thread_mutex_destroy(mutex->mutex);
    free(mutex->mutex);
}

int threading_mutex_lock_sgx(mbedtls_threading_mutex_t *mutex)
{
    if (mutex == NULL || mutex->is_valid != 0) return -1;
    return sgx_thread_mutex_lock(mutex->mutex);
}

int threading_mutex_unlock_sgx(mbedtls_threading_mutex_t *mutex)
{
    if (mutex == NULL || mutex->is_valid != 0) return -1;
    return sgx_thread_mutex_unlock(mutex->mutex);
}

void mbedtls_threading_set_sgx()
{
    mbedtls_threading_set_alt(
        threading_mutex_init_sgx, threading_mutex_free_sgx,
        threading_mutex_lock_sgx, threading_mutex_unlock_sgx);
}