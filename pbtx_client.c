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

    pb_ostream_t permstream = pb_ostream_from_buffer(msg.permision_bytes.bytes, sizeof(msg.permision_bytes.bytes));
    if( !pb_encode(&permstream, pbtx_Permission_fields, &perm) ) {
        ESP_LOGE(TAG, "perm pb_encode error: %s", PB_GET_ERROR(&permstream));
        return -1;
    }
    msg.permision_bytes.size = permstream.bytes_written;

    size_t signature_size;
    if( pbtx_sigp_sign(msg.permision_bytes.bytes, msg.permision_bytes.size,
                       msg.signature.bytes, sizeof(msg.signature.bytes), &signature_size) != 0 ) {
        return -1;
    }
    msg.signature.size = signature_size;

    pb_ostream_t stream = pb_ostream_from_buffer(buf, buflen);
    if( !pb_encode(&stream, pbtxrpc_RegisterAccount_fields, &msg) ) {
        ESP_LOGE(TAG, "pb_encode error: %s", PB_GET_ERROR(&stream));
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
    pbtxrpc_RegisterAccountResponse msg;
    pb_istream_t msg_stream = pb_istream_from_buffer(buf, buflen);
    if( !pb_decode(&msg_stream, pbtxrpc_RegisterAccountResponse_fields, &msg) ) {
        ESP_LOGE(TAG, "Error while decoding pbtxrpc_RegisterAccountResponse: %s", msg_stream.errmsg);
        return -1;
    }

    if( pbtx_sigp_check_last_rpc_msghash(msg.request_hash.bytes, msg.request_hash.size) != 0 ) {
        return -1;
    }

    if( msg.status != pbtxrpc_RegisterAccountResponse_StatusCode_SUCCESS ) {
        ESP_LOGE(TAG, "RegisterAccountResponse.status is not a SUCCESS: %d", msg.status);
        return msg.status;
    }

    if( pbtx_client_has_identity() ) {
        if( msg.network_id != trx_body.network_id ) {
            ESP_LOGE(TAG, "RegisterAccountResponse.network_id is not the same as previously known. Expected: %lld, received: %lld",
                     trx_body.network_id, msg.network_id);
            return -1;
        }

        if( msg.last_seqnum != trx_body.seqnum || msg.prev_hash != trx_body.prev_hash ) {
            if( pbtx_sigp_upd_seq(msg.last_seqnum, msg.prev_hash) != 0 ) {
                return -1;
            }
            trx_body.seqnum = msg.last_seqnum;
            trx_body.prev_hash = msg.prev_hash;
        }
    }
    else {
        if( pbtx_sigp_upd_network(msg.network_id, msg.last_seqnum, msg.prev_hash) != 0 ) {
            return -1;
        }
        trx_body.network_id = msg.network_id;
        trx_body.seqnum = msg.last_seqnum;
        trx_body.prev_hash = msg.prev_hash;
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

    pb_ostream_t bodystream = pb_ostream_from_buffer(trx.body.bytes, sizeof(trx.body.bytes));
    if( !pb_encode(&bodystream, pbtx_TransactionBody_fields, &trx_body) ) {
        ESP_LOGE(TAG, "trx_body pb_encode error: %s", PB_GET_ERROR(&bodystream));
        return -1;
    }
    trx.body.size = bodystream.bytes_written;

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
    return 0;

rollback:
    trx_body.seqnum = old_seqnum;
    return -1;
}
