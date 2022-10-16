#include "pbtx_client.h"

#include "mbedtls/platform.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"

size_t pbtx_create_private_key(uint8_t type, char* buf, size_t buflen)
{
    int ret;
    mbedtls_ecdsa_context ctx;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "ecdsa";

    mbedtls_ecdsa_init( &ctx );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    
    mbedtls_entropy_init( &entropy );
    
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                                       (const unsigned char *) pers,
                                       strlen( pers ) ) ) != 0 )  {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        return -1;
    }
    
    if( ( ret = mbedtls_ecdsa_genkey( &ctx,
                                      type == PBTX_KEY_TYPE_ANTELOPE_K1 ? MBEDTLS_ECP_DP_SECP256K1 : MBEDTLS_ECP_DP_SECP256R1,
                                      mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 ) {
        mbedtls_printf( " failed\n  ! mbedtls_ecdsa_genkey returned %d\n", ret );
        return -1;
    }

    mbedtls_printf( " ok (key size: %d bits)\n", (int) ctx.MBEDTLS_PRIVATE(grp).pbits );
    return 0;
}

