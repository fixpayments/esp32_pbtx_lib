#include "pbtx_client.h"
#include "pbtx_signature_provider.h"
#include "pbtx.pb.h"
#include <pb_encode.h>

#include "esp_log.h"
static const char* TAG = "pbtx_client";


int pbtx_client_init()
{
    return pbtx_sigp_init();
}

int pbtx_client_get_public_key(unsigned char* buf, size_t buflen, size_t* olen)
{
    pbtx_PublicKey pubkey;
    pubkey.type = pbtx_KeyType_EOSIO_KEY;

    int err;
    *olen = 0;

    size_t pubkey_bytes_size;
    if( (err = pbtx_sigp_get_public_key(pubkey.key_bytes.bytes,
                                        sizeof(pubkey.key_bytes.bytes),
                                        &pubkey_bytes_size)) != 0 ) {
        ESP_LOGE(TAG, "pbtx_sigp_get_public_key returned %d", err);
        return err;
    }

    pubkey.key_bytes.size = pubkey_bytes_size;

    ESP_LOGI(TAG, "pubkey_bytes_size: %d", pubkey_bytes_size);
    ESP_LOG_BUFFER_HEX(TAG, pubkey.key_bytes.bytes, sizeof(pubkey.key_bytes.bytes));

    pb_ostream_t stream = pb_ostream_from_buffer(buf, buflen);
    if( !pb_encode(&stream, pbtx_PublicKey_fields, &pubkey) ) {
        ESP_LOGE(TAG, "pb_encode error: %s", PB_GET_ERROR(&stream));
        return -1;
    }

    *olen = stream.bytes_written;
    return 0;
}
