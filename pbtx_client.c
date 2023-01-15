#include "pbtx_client.h"
#include "pbtx_signature_provider.h"
#include "pbtx.pb.h"
#include "pbtx-rpc.pb.h"
#include <pb_encode.h>
#include <pb_decode.h>

#include "esp_log.h"
static const char* TAG = "pbtx_client";

static pbtx_TransactionBody trx_body;
static pbtx_Transaction trx;


int pbtx_client_init()
{
    if( pbtx_sigp_init() != 0 ) {
        return -1;
    }

    if( pbtx_sigp_has_identity() ) {
        if( pbtx_sigp_get_identity(&trx_body.network_id, &trx_body.actor, &trx_body.seqnum, &trx_body.prev_hash) != 0 ) {
            return -1;
        }
    }
    else {
        trx_body.network_id = 0;
        trx_body.actor = 0;
    }

    ESP_LOGI(TAG, "pbtx_client_init: network_id=%llu, actor=%llu",  trx_body.network_id, trx_body.actor);

    trx_body.cosignors_count = 0;
    return 0;
}


static int pbtx_client_get_pubkey(pbtx_PublicKey* pubkey)
{
    pubkey->type = pbtx_KeyType_EOSIO_KEY;

    int err;
    size_t pubkey_bytes_size;
    if( (err = pbtx_sigp_get_public_key(pubkey->key_bytes.bytes,
                                        sizeof(pubkey->key_bytes.bytes),
                                        &pubkey_bytes_size)) != 0 ) {
        ESP_LOGE(TAG, "pbtx_sigp_get_public_key returned %d", err);
        return err;
    }
    pubkey->key_bytes.size = pubkey_bytes_size;

    return 0;
}


int pbtx_client_sign_data(const unsigned char* data, size_t datalen, unsigned char* sig_buf, size_t buflen, size_t* sig_size)
{
    return pbtx_sigp_sign(data, datalen, sig_buf, buflen, sig_size);
}


int pbtx_client_has_identity()
{
    return (trx_body.network_id != 0 && trx_body.actor != 0) ? 1:0;
}



int pbtx_client_rpc_request_response(unsigned char* buf, size_t buflen, unsigned char* data_buf, size_t data_buflen, size_t* data_size)
{
    pbtxrpc_RequestResponse msg;
    pb_istream_t msg_stream = pb_istream_from_buffer(buf, buflen);
    if( !pb_decode(&msg_stream, pbtxrpc_RequestResponse_fields, &msg) ) {
        ESP_LOGE(TAG, "Error while decoding pbtxrpc_RequestResponse: %s", msg_stream.errmsg);
        return -1;
    }

    if( pbtx_sigp_check_last_rpc_msghash(msg.request_hash.bytes, msg.request_hash.size) != 0 ) {
        return -1;
    }

    if( msg.status != pbtxrpc_RequestResponse_StatusCode_SUCCESS ) {
        ESP_LOGE(TAG, "RequestResponse.status is not a SUCCESS: %d", msg.status);
        return msg.status;
    }

    if( data_buf != NULL ) {
        *data_size = msg.data.size;
        if( msg.data.size > 0 ) {
            if( msg.data.size > data_buflen ) {
                ESP_LOGE(TAG, "pbtx_client_rpc_request_response: data_buflen is too short. Got %d, need %d", data_buflen, msg.data.size);
                return -1;
            }
            memcpy(data_buf, msg.data.bytes, msg.data.size);
        }
    }

    return 0;
}





int pbtx_client_rpc_register_account(unsigned char* buf, size_t buflen, size_t* olen)
{
    pbtx_Permission perm;
    if( !pbtx_client_has_identity() ) {
        if( pbtx_sigp_gen_actor_id(&trx_body.actor) != 0 ) {
            return -1;
        }
    }
    perm.actor = trx_body.actor;

    *olen = 0;
    pbtxrpc_RegisterAccount msg;

    perm.threshold = 1;
    perm.keys_count = 1;
    perm.keys[0].has_key = true;
    if( pbtx_client_get_pubkey( &(perm.keys[0].key) ) != 0 ) {
        return -1;
    }
    perm.keys[0].weight = 1;

    pb_ostream_t permstream = pb_ostream_from_buffer(msg.permission_bytes.bytes, sizeof(msg.permission_bytes.bytes));
    if( !pb_encode(&permstream, pbtx_Permission_fields, &perm) ) {
        ESP_LOGE(TAG, "perm pb_encode error: %s", PB_GET_ERROR(&permstream));
        return -1;
    }
    msg.permission_bytes.size = permstream.bytes_written;

    size_t signature_size;
    if( pbtx_sigp_sign(msg.permission_bytes.bytes, msg.permission_bytes.size,
                       msg.signature.bytes, sizeof(msg.signature.bytes), &signature_size) != 0 ) {
        return -1;
    }
    msg.signature.size = signature_size;

    msg.credentials.size = 0;

    pb_ostream_t stream = pb_ostream_from_buffer(buf, buflen);
    if( !pb_encode(&stream, pbtxrpc_RegisterAccount_fields, &msg) ) {
        ESP_LOGE(TAG, "pb_encode error: %s, max_size: %d, written: %d",
                 PB_GET_ERROR(&stream), stream.max_size, stream.bytes_written);
        return -1;
    }

    if( pbtx_sigp_save_last_rpc_msghash(buf, stream.bytes_written) != 0 ) {
        return -1;
    }

    *olen = stream.bytes_written;
    return 0;
}




int pbtx_client_rpc_register_account_response(unsigned char* buf, size_t buflen)
{
    unsigned char data[64];
    size_t data_size;
    int res = pbtx_client_rpc_request_response(buf, buflen, data, 64, &data_size);
    if( res != 0 ) {
        ESP_LOGE(TAG, "pbtx_client_rpc_request_response returned %d", res);
        return res;
    }

    pbtxrpc_AccountSeqData seqdata;
    pb_istream_t seqdata_stream = pb_istream_from_buffer(data, data_size);
    if( !pb_decode(&seqdata_stream, pbtxrpc_AccountSeqData_fields, &seqdata) ) {
        ESP_LOGE(TAG, "Error while decoding pbtxrpc_AccountSeqData: %s", seqdata_stream.errmsg);
        return -1;
    }

    if( pbtx_client_has_identity() ) {
        if( seqdata.network_id != trx_body.network_id ) {
            ESP_LOGE(TAG, "RegisterAccountResponse.network_id is not the same as previously known. Expected: %lld, received: %lld",
                     trx_body.network_id, seqdata.network_id);
            return -1;
        }

        if( seqdata.last_seqnum != trx_body.seqnum || seqdata.prev_hash != trx_body.prev_hash ) {
            if( pbtx_sigp_upd_seq(seqdata.last_seqnum, seqdata.prev_hash) != 0 ) {
                return -1;
            }
            trx_body.seqnum = seqdata.last_seqnum;
            trx_body.prev_hash = seqdata.prev_hash;
        }
    }
    else {
        if( pbtx_sigp_upd_network(seqdata.network_id, seqdata.last_seqnum, seqdata.prev_hash) != 0 ) {
            return -1;
        }
        trx_body.network_id = seqdata.network_id;
        trx_body.seqnum = seqdata.last_seqnum;
        trx_body.prev_hash = seqdata.prev_hash;
    }

    return 0;
}



int pbtx_client_rpc_transaction(uint32_t transaction_type, const unsigned char* transaction_content, size_t content_length,
                                unsigned char* buf, size_t buflen, size_t* olen)
{
    if( !pbtx_client_has_identity() ) {
        return -1;
    }

    if( content_length > sizeof(trx_body.transaction_content.bytes) ) {
        ESP_LOGE(TAG, "pbtx_client_rpc_transaction: content_length is too big. Got %d, max: %d",
                 content_length, sizeof(trx_body.transaction_content.bytes));
        return -1;
    }

    /* saving the old values for rolling back in case of failure */
    uint32_t old_seqnum = trx_body.seqnum;

    trx_body.seqnum++;
    trx_body.transaction_type = transaction_type;
    memcpy(trx_body.transaction_content.bytes, transaction_content, content_length);
    trx_body.transaction_content.size = content_length;

    pb_ostream_t bodystream = pb_ostream_from_buffer(trx.body.bytes, sizeof(trx.body.bytes));
    if( !pb_encode(&bodystream, pbtx_TransactionBody_fields, &trx_body) ) {
        ESP_LOGE(TAG, "trx_body pb_encode error: %s", PB_GET_ERROR(&bodystream));
        return -1;
    }
    trx.body.size = bodystream.bytes_written;

    /* ESP_LOGI(TAG, "body length: %d", trx.body.size); */

    trx.authorities_count = 1;
    trx.authorities[0].type = pbtx_KeyType_EOSIO_KEY;
    trx.authorities[0].sigs_count = 1;
    size_t sig_size;
    if( pbtx_sigp_sign(trx.body.bytes, trx.body.size,
                       trx.authorities[0].sigs[0].bytes, sizeof(trx.authorities[0].sigs[0].bytes), &sig_size) != 0 ) {
        goto rollback;
    }
    trx.authorities[0].sigs[0].size = sig_size;

    pb_ostream_t trxstream = pb_ostream_from_buffer(buf, buflen);
    if( !pb_encode(&trxstream, pbtx_Transaction_fields, &trx) ) {
        ESP_LOGE(TAG, "trx pb_encode error: %s", PB_GET_ERROR(&trxstream));
        goto rollback;
    }
    *olen = trxstream.bytes_written;

    trx_body.prev_hash = pbtx_sigp_calc_prevhash(trx.body.bytes, trx.body.size);
    pbtx_sigp_upd_seq(trx_body.seqnum, trx_body.prev_hash);

    if( pbtx_sigp_save_last_rpc_msghash(buf, trxstream.bytes_written) != 0 ) {
        return -1;
    }

    return 0;

rollback:
    trx_body.seqnum = old_seqnum;
    return -1;
}


int pbtx_client_rpc_transaction_response(unsigned char* buf, size_t buflen)
{
    int res = pbtx_client_rpc_request_response(buf, buflen, NULL, 0, NULL);
    if( res != 0 ) {
        ESP_LOGE(TAG, "pbtx_client_rpc_request_response returned %d", res);
    }
    return res;
}
