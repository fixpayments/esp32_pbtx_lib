#include "pbtx_signature_provider.h"

#include <string.h>

#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"

#include "mbedtls/platform.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/sha256.h"

#include "nvs_flash.h"
#include "nvs.h"

static const char* TAG = "pbtx_signature_provider";

static mbedtls_pk_context privkey_ctx;



#define STORAGE_NAMESPACE "pbtx_sigp"
#define PEM_KEY_BUFLEN 1000
#define PEM_KEY_NVSKEY "privkey"

int pbtx_sigp_init()
{
    esp_err_t err;

    err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        // NVS partition was truncated and needs to be erased
        // Retry nvs_flash_init
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK( err );

    mbedtls_pk_init( &privkey_ctx );

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "ecdsa";

    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );

    if( ( err = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                                       (const unsigned char *) pers,
                                       strlen( pers ) ) ) != 0 )  {
        ESP_LOGE(TAG, "mbedtls_ctr_drbg_seed returned %x\n", err );
        return -1;
    }

    nvs_handle_t nvsh;

    if( (err = nvs_open(STORAGE_NAMESPACE, NVS_READWRITE, &nvsh)) != ESP_OK ) {
        ESP_LOGE(TAG, "nvs_open returned %x", err);
        return err;
    }

    unsigned char* pem_key_buf = malloc(PEM_KEY_BUFLEN);
    size_t pem_key_len = 0;
    err = nvs_get_str(nvsh, PEM_KEY_NVSKEY, NULL, &pem_key_len);
    if( err == ESP_OK ) {
        /* the private key is found on NVS */
        if( pem_key_len > PEM_KEY_BUFLEN ) {
            ESP_LOGE(TAG, "private key string on NVS is too long: %d bytes", pem_key_len);
            return -1;
        }

        if( (err = nvs_get_str(nvsh, PEM_KEY_NVSKEY, (char*) pem_key_buf, &pem_key_len)) != ESP_OK ) {
            ESP_LOGE(TAG, "Cannot read private key from NVS: %x", err);
            return -1;
        }

        if( (err = mbedtls_pk_parse_key(&privkey_ctx, pem_key_buf, pem_key_len, NULL, 0,
                                        mbedtls_ctr_drbg_random, &ctr_drbg)) != 0 ) {
            ESP_LOGE(TAG, "mbedtls_pk_parse_key returned error: %x", err);
            return -1;
        }

        ESP_LOGI(TAG, "Loaded key from NVS");
    }
    else if( err == ESP_ERR_NVS_NOT_FOUND ) {
        ESP_LOGI(TAG, "No private key on NVS, generating a new one...");

        if( ( err = mbedtls_pk_setup( &privkey_ctx,
                                      mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY) ) ) != 0 ) {
            ESP_LOGE(TAG, "mbedtls_pk_setup returned -0x%04x", (unsigned int) -err );
            return -1;
        }

        if( ( err = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1,
                                        mbedtls_pk_ec( privkey_ctx ),
                                        mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 ) {
            ESP_LOGE(TAG, "mbedtls_ecdsa_genkey returned -0x%04x", (unsigned int) -err );
            return -1;
        }

        if( ( err = mbedtls_pk_write_key_pem( &privkey_ctx, pem_key_buf, PEM_KEY_BUFLEN ) ) != 0 ) {
            ESP_LOGE(TAG, "mbedtls_pk_write_key_pem returned -0x%04x", (unsigned int) -err );
            return -1;
        }

        ESP_LOGI(TAG, "Saving the key to NVS...");

        if( (err = nvs_set_str(nvsh, PEM_KEY_NVSKEY, (char*) pem_key_buf)) != ESP_OK ) {
            ESP_LOGE(TAG, "nvs_set_str returned %x", err);
            return -1;
        }
    }

    if( !mbedtls_pk_can_do(&privkey_ctx, MBEDTLS_PK_ECKEY) ) {
        ESP_LOGE(TAG, "This not an ECKEY");
        return -1;
    }

    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
    
    ESP_LOGI(TAG, "pbtx_sigp_init() finsihed. Public key:");

    if( (err = mbedtls_pk_write_pubkey_pem( &privkey_ctx, pem_key_buf, PEM_KEY_BUFLEN)) != 0 ) {
            ESP_LOGE(TAG, "mbedtls_pk_write_pubkey_pem returned -0x%04x", (unsigned int) -err );
            return -1;
    }

    printf("%s\n", pem_key_buf);

    return 0;
}




int pbtx_sigp_get_public_key(unsigned char* buf, size_t buflen, size_t* olen)
{
    if( !mbedtls_pk_can_do(&privkey_ctx, MBEDTLS_PK_ECKEY) ) {
        ESP_LOGE(TAG, "Private key is not initialized");
        return -1;
    }

    if( buflen < 34 ) {
        ESP_LOGE(TAG, "Buffer must be at least 34 bytes long");
        return -1;
    }

    *buf = PBTX_KEY_TYPE_ANTELOPE_R1;
    buf++; buflen--;

    const mbedtls_ecp_keypair *ec = mbedtls_pk_ec( privkey_ctx );

    int err;

    if( (err = mbedtls_ecp_point_write_binary( &(ec->MBEDTLS_PRIVATE(grp)), &(ec->MBEDTLS_PRIVATE(Q)),
                                               MBEDTLS_ECP_PF_COMPRESSED, olen,
                                               buf, buflen ) ) != 0 ) {
        ESP_LOGE(TAG, "mbedtls_ecp_point_write_binary returned -0x%04x", (unsigned int) -err );
        return -1;
    }

    (*olen)++;
    return 0;
}




int pbtx_sigp_sign(const unsigned char* data, size_t datalen, unsigned char* sig_buf, size_t buflen, size_t* sig_size)
{
    esp_err_t err;
    
    if( !mbedtls_pk_can_do(&privkey_ctx, MBEDTLS_PK_ECKEY) ) {
        ESP_LOGE(TAG, "Private key is not initialized");
        return -1;
    }
    
    if( buflen < 66 ) {
        ESP_LOGE(TAG, "Buffer must be at least 64 bytes long");
        return -1;
    }

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "ecdsa";

    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );

    
    if( ( err = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                                       (const unsigned char *) pers,
                                       strlen( pers ) ) ) != 0 )  {
        ESP_LOGE(TAG, "mbedtls_ctr_drbg_seed returned -0x%04x", (unsigned int) -err );
        return -1;
    }
    
    unsigned char hash[32];
    mbedtls_sha256_context md_ctx;
    mbedtls_sha256_init( &md_ctx );
    mbedtls_sha256_starts( &md_ctx, 0 );
    mbedtls_sha256_update( &md_ctx, data, datalen );
    mbedtls_sha256_finish( &md_ctx, hash );
    mbedtls_sha256_free( &md_ctx );

    
    const mbedtls_ecp_keypair *ec = mbedtls_pk_ec( privkey_ctx );

    mbedtls_mpi r, s;
    mbedtls_mpi_init( &r ); mbedtls_mpi_init( &s );
    
    if( (err = mbedtls_ecdsa_sign( &(ec->MBEDTLS_PRIVATE(grp)), &r, &s, &(ec->MBEDTLS_PRIVATE(d)),
                                   hash, sizeof( hash ),
                                   mbedtls_ctr_drbg_random, &ctr_drbg )) != 0 ) {
        ESP_LOGE(TAG, "mbedtls_ecdsa_sign returned -0x%04x", (unsigned int) -err );
        return -1;
    }
    
    /* checkAndHandleLowS */
    
    mbedtls_mpi halforder;
    mbedtls_mpi_init(&halforder);
    if( (err = mbedtls_mpi_copy(&halforder, &(ec->MBEDTLS_PRIVATE(grp).N)) ) != 0 ) {
        ESP_LOGE(TAG, "mbedtls_mpi_copy returned -0x%04x", (unsigned int) -err );
        return -1;
    }   
    
    if( (err = mbedtls_mpi_shift_r( &halforder, 1 ) ) != 0 ) {
        ESP_LOGE(TAG, "mbedtls_mpi_shift_r returned -0x%04x", (unsigned int) -err );
        return -1;
    }   

    if( mbedtls_mpi_cmp_mpi( &s, &halforder ) > 0 ) {
        mbedtls_mpi new_s;
        mbedtls_mpi_init(&new_s);

        ESP_LOGE(TAG, "high s");
        
        if( (err = mbedtls_mpi_sub_mpi(&new_s, &(ec->MBEDTLS_PRIVATE(grp).N), &s)) != 0 ) {
            ESP_LOGE(TAG, "mbedtls_mpi_sub_mpi returned -0x%04x", (unsigned int) -err );
            return -1;
        }

        if( (err = mbedtls_mpi_copy(&s, &new_s)) != 0 ) {
            ESP_LOGE(TAG, "mbedtls_mpi_copy returned -0x%04x", (unsigned int) -err );
            return -1;
        }   
        
        mbedtls_mpi_free( &new_s );
    }
    
    mbedtls_mpi_free(&halforder);

    int len = mbedtls_mpi_size( &s );
    mbedtls_mpi_write_binary( &s, sig_buf, len );
    mbedtls_mpi_write_binary( &r, sig_buf + len, len);
    *sig_size = len * 2;

    
    mbedtls_mpi_free( &r ); mbedtls_mpi_free( &s );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
    return 0;
}
