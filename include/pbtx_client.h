
#ifndef _PBTX_CLIENT_H
#define _PBTX_CLIENT_H

#include "pbtx.pb.h"

#define PBTX_KEY_TYPE_ANTELOPE_K1 0
#define PBTX_KEY_TYPE_ANTELOPE_R1 1



int pbtx_create_private_key(uint8_t type, unsigned char* buf, size_t buflen);























#endif
