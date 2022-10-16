#include "pbtx_client.h"

#include "mbedtls/platform.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/pk.h"
#include "mbedtls/ecdsa.h"

int pbtx_create_private_key(uint8_t type, unsigned char* buf, size_t buflen)
{
    int ret;
    mbedtls_pk_context key;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "ecdsa";

    mbedtls_pk_init( &key );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    
    mbedtls_entropy_init( &entropy );

    mbedtls_printf( "\n  . Generating the private key ..." );
    fflush( stdout );

    if( ( ret = mbedtls_pk_setup( &key,
                                  mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY) ) ) != 0 ) {
        mbedtls_printf( " failed\n  !  mbedtls_pk_setup returned -0x%04x", (unsigned int) -ret );
        return -1;
    }
    
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                                       (const unsigned char *) pers,
                                       strlen( pers ) ) ) != 0 )  {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        return -1;
    }

    if( ( ret = mbedtls_ecp_gen_key(type == PBTX_KEY_TYPE_ANTELOPE_K1 ? MBEDTLS_ECP_DP_SECP256K1 : MBEDTLS_ECP_DP_SECP256R1,
                                    mbedtls_pk_ec( key ),
                                    mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 ) {
        mbedtls_printf( " failed\n  ! mbedtls_ecdsa_genkey returned %d\n", ret );
        return -1;
    }

    if( ( ret = mbedtls_pk_write_key_pem( &key, buf, buflen ) ) != 0 ) {
        mbedtls_printf( " failed\n  ! mbedtls_pk_write_key_pem returned %d\n", ret );
        return -1;
    }

    return 0;
}

