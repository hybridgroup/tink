/* Declarations control.c needs to compile. The generator never calls them. */
#pragma once
#include <stddef.h>
#include <stdint.h>
typedef int psa_status_t;
typedef struct { int unused; } psa_hash_operation_t;
#define PSA_HASH_OPERATION_INIT {0}
#define PSA_SUCCESS 0
#define PSA_ALG_SHA_256 0
psa_status_t psa_hash_setup(psa_hash_operation_t *, int);
psa_status_t psa_hash_update(psa_hash_operation_t *, const uint8_t *, size_t);
psa_status_t psa_hash_finish(psa_hash_operation_t *, uint8_t *, size_t, size_t *);
psa_status_t psa_hash_abort(psa_hash_operation_t *);
