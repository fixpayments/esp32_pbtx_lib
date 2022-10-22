
#ifndef _PBTX_CLIENT_H
#define _PBTX_CLIENT_H

#include "pbtx.pb.h"

#define PBTX_KEY_TYPE_ANTELOPE_K1 0
#define PBTX_KEY_TYPE_ANTELOPE_R1 1


#include "mbedtls/pk.h"

typedef struct pbtx_client_context
{
    mbedtls_pk_context* key;
} pbtx_client_context;


void pbtx_init_client(pbtx_client_context* ctx);
        

















#endif
