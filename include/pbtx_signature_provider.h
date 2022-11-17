
#ifndef _PBTX_SIGNATURE_PROVIDER_H
#define _PBTX_SIGNATURE_PROVIDER_H


#define PBTX_KEY_TYPE_ANTELOPE_K1 0
#define PBTX_KEY_TYPE_ANTELOPE_R1 1

#include <stdint.h>
#include <stddef.h>

int pbtx_sigp_init();

int pbtx_sigp_get_public_key(unsigned char* buf, size_t buflen, size_t* olen);

int pbtx_sigp_sign(const unsigned char* data, size_t datalen, unsigned char* sig_buf, size_t buflen, size_t* sig_size);

/* returns 1 if identity is initialized */
int pbtx_sigp_has_identity();

/* generates the actor ID based on MAC address or hash of previous
 * actor ID. Returns 1 if the identity is finalized and cannot be
 * changed. Returns 0 on success */
int pbtx_sigp_gen_actor_id(uint64_t *actor_id);

/* returns 0 on success */
int pbtx_sigp_save_last_rpc_msghash(const unsigned char* data, size_t datalen);

/* returns 0 on success */
int pbtx_sigp_get_last_rpc_msghash(unsigned char* buf, size_t buflen, size_t* olen);

/* this finalizes the identity. Subsequent calls can decrease
 * last_seqnum and modify prev_hash, but network_id cannot be
 * changed. Returns 0 on success */
int pbtx_sigp_upd_network(uint64_t network_id, uint32_t last_seqnum, uint64_t prev_hash);

/* retrieves current values. Returns 0 on success */
int pbtx_sigp_get_identity(uint64_t *network_id, uint64_t *actor_id, uint32_t *last_seqnum, uint64_t *prev_hash);

/* stores the increased last_seqnum and new prev_hash. Returns 0 on success */
int pbtx_sigp_upd_seq(uint32_t last_seqnum, uint64_t prev_hash);

/* erases the identity. Returns 0 on success */
int pbtx_sigp_erase_identity();


#endif
