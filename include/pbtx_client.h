
#ifndef _PBTX_CLIENT_H
#define _PBTX_CLIENT_H

#include <stddef.h>


int pbtx_client_init();
        
int pbtx_client_get_public_key(unsigned char* buf, size_t buflen, size_t* olen);

int pbtx_client_sign_data(const unsigned char* data, size_t datalen, unsigned char* sig_buf, size_t buflen, size_t* sig_size);



#endif
