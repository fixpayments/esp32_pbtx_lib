#include "pbtx_signature_provider.h"

#include <string.h>

#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"

#include "mbedtls/platform.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"

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
            ESP_LOGE(TAG, "mbedtls_ecdsa_genkey returned %x\n", err );
            return -1;
        }

        if( ( err = mbedtls_pk_write_key_pem( &privkey_ctx, pem_key_buf, PEM_KEY_BUFLEN ) ) != 0 ) {
            ESP_LOGE(TAG, "mbedtls_pk_write_key_pem returned %x\n", err );
            return -1;
        }

        ESP_LOGI(TAG, "Saving the key to NVS...");

        if( (err = nvs_set_str(nvsh, PEM_KEY_NVSKEY, (char*) pem_key_buf)) != ESP_OK ) {
            ESP_LOGE(TAG, "nvs_set_str returned %x", err);
            return -1;
        }
    }

    ESP_LOGI(TAG, "pbtx_sigp_init() finsihed. Public key:");

    if( (err = mbedtls_pk_write_pubkey_pem( &privkey_ctx, pem_key_buf, PEM_KEY_BUFLEN)) != 0 ) {
            ESP_LOGE(TAG, "mbedtls_pk_write_pubkey_pem returned %x\n", err );
            return -1;
    }

    printf("%s\n", pem_key_buf);

    return 0;
}



static void dump_buf( const char *title, unsigned char *buf, size_t len )
{
    size_t i;
    mbedtls_printf( "%s", title );
    for( i = 0; i < len; i++ ) {
        mbedtls_printf("%c%c",
                       "0123456789ABCDEF" [buf[i] / 16],
                       "0123456789ABCDEF" [buf[i] % 16] );
    }
    mbedtls_printf( "\n" );
}
