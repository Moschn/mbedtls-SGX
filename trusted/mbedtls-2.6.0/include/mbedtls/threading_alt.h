#ifndef MBEDTLS_THREADING_ALT_H
#define MBEDTLS_THREADING_ALT_H

#include "sgx_thread.h"

typedef struct
{
    sgx_thread_mutex_t *mutex;
    char is_valid;
} mbedtls_threading_mutex_t;

void threading_mutex_init_sgx(mbedtls_threading_mutex_t *mutex);

void threading_mutex_free_sgx(mbedtls_threading_mutex_t *mutex);

int threading_mutex_lock_sgx(mbedtls_threading_mutex_t *mutex);

int threading_mutex_unlock_sgx(mbedtls_threading_mutex_t *mutex);

extern void mbedtls_threading_set_alt(void (*mutex_init)(mbedtls_threading_mutex_t *),
                                      void (*mutex_free)(mbedtls_threading_mutex_t *),
                                      int (*mutex_lock)(mbedtls_threading_mutex_t *),
                                      int (*mutex_unlock)(mbedtls_threading_mutex_t *));

void mbedtls_threading_set_sgx();

#endif /* threading?alt.h */