
#ifndef _PBTX_SIGNATURE_PROVIDER_H
#define _PBTX_SIGNATURE_PROVIDER_H


#define PBTX_KEY_TYPE_ANTELOPE_K1 0
#define PBTX_KEY_TYPE_ANTELOPE_R1 1


#include "mbedtls/pk.h"



int pbtx_sigp_init();

int pbtx_sigp_get_public_key(unsigned char* buf, size_t buflen, size_t* olen);

int pbtx_sigp_sign(const unsigned char* data, size_t datalen, unsigned char* sig_buf, size_t buflen, size_t* sig_size);


#endif
