
#ifndef _PBTX_CLIENT_H
#define _PBTX_CLIENT_H

#include <stddef.h>
#include <stdint.h>

/* one-time client initialization. Returns 0 on success */
int pbtx_client_init();

/* signs the input byte array with the stores provate key. Retuns 0 on success */
int pbtx_client_sign_data(const unsigned char* data, size_t datalen, unsigned char* sig_buf, size_t buflen, size_t* sig_size);

/* returns true if the network registration is finalized */
int pbtx_client_has_identity();

/* writes a pbtxrpc.RegisterAccount message into the buffer */
int pbtx_client_rpc_register_account(unsigned char* buf, size_t buflen, size_t* olen);

/* takes a pbtxrpc.RegisterAccountResponse and saves the identity.
   Returns 0 on success.
   On registration failure, returns RegisterAccountResponse.status. Otherwise, returns -1 */
int pbtx_client_rpc_register_account_response(unsigned char* buf, size_t buflen);

/* writes a pbtx.Transaction message into the buffer. Returns 0 on success */
int pbtx_client_rpc_transaction(uint32_t transaction_type, const unsigned char* transaction_content, size_t content_length,
                                unsigned char* buf, size_t buflen, size_t* olen);

#endif
