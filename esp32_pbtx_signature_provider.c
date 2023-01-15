#include "pbtx_signature_provider.h"

#include <string.h>

#include "esp_log.h"

#include "mbedtls/platform.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/sha256.h"
#include "mbedtls/pk.h"

#include "nvs_flash.h"
#include "nvs.h"
#include "esp_mac.h"

static const char* TAG = "pbtx_sigp";

static mbedtls_pk_context privkey_ctx;


#define PEM_KEY_BUFLEN 1000

#define STORAGE_NAMESPACE "pbtx_sigp"

#define NVSKEY_PEM_KEY        "privkey"
#define NVSKEY_IDENTITY       "identity"
#define NVSKEY_SEQ            "seq"
#define NVSKEY_RPC_MSGHASH    "msghash"

typedef struct s_pbtx_identity {
    uint64_t network_id;
    uint64_t actor_id;
} pbtx_identity;

typedef struct s_pbtx_seq {
    uint32_t last_seqnum;
    uint64_t prev_hash;
} pbtx_seq;


int pbtx_sigp_init()
{
    esp_err_t err = 0;

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
        goto cleanup;
    }

    nvs_handle_t nvsh;

    if( (err = nvs_open(STORAGE_NAMESPACE, NVS_READWRITE, &nvsh)) != ESP_OK ) {
        ESP_LOGE(TAG, "nvs_open returned %x", err);
        goto cleanup;
    }

    unsigned char* pem_key_buf = malloc(PEM_KEY_BUFLEN);
    size_t pem_key_len = 0;
    err = nvs_get_str(nvsh, NVSKEY_PEM_KEY, NULL, &pem_key_len);
    if( err == ESP_OK ) {
        /* the private key is found on NVS */
        if( pem_key_len > PEM_KEY_BUFLEN ) {
            ESP_LOGE(TAG, "private key string on NVS is too long: %d bytes", pem_key_len);
            err = -1; goto cleanup;
        }

        if( (err = nvs_get_str(nvsh, NVSKEY_PEM_KEY, (char*) pem_key_buf, &pem_key_len)) != ESP_OK ) {
            ESP_LOGE(TAG, "Cannot read private key from NVS: %x", err);
            goto cleanup;
        }

        if( (err = mbedtls_pk_parse_key(&privkey_ctx, pem_key_buf, pem_key_len, NULL, 0,
                                        mbedtls_ctr_drbg_random, &ctr_drbg)) != 0 ) {
            ESP_LOGE(TAG, "mbedtls_pk_parse_key returned error: %x", err);
            goto cleanup;
        }

        ESP_LOGI(TAG, "Loaded key from NVS");
    }
    else if( err == ESP_ERR_NVS_NOT_FOUND ) {
        ESP_LOGI(TAG, "No private key on NVS, generating a new one...");

        if( ( err = mbedtls_pk_setup( &privkey_ctx,
                                      mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY) ) ) != 0 ) {
            ESP_LOGE(TAG, "mbedtls_pk_setup returned -0x%04x", (unsigned int) -err );
            goto cleanup;
        }

        if( ( err = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1,
                                        mbedtls_pk_ec( privkey_ctx ),
                                        mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 ) {
            ESP_LOGE(TAG, "mbedtls_ecdsa_genkey returned -0x%04x", (unsigned int) -err );
            goto cleanup;
        }

        if( ( err = mbedtls_pk_write_key_pem( &privkey_ctx, pem_key_buf, PEM_KEY_BUFLEN ) ) != 0 ) {
            ESP_LOGE(TAG, "mbedtls_pk_write_key_pem returned -0x%04x", (unsigned int) -err );
            goto cleanup;
        }

        ESP_LOGI(TAG, "Saving the key to NVS...");

        if( (err = nvs_set_str(nvsh, NVSKEY_PEM_KEY, (char*) pem_key_buf)) != ESP_OK ) {
            ESP_LOGE(TAG, "nvs_set_str returned %x", err);
            goto cleanup;
        }

        if( (err =  nvs_commit(nvsh)) != ESP_OK ) {
            ESP_LOGE(TAG, "nvs_commit returned %x", err);
            goto cleanup;
        }
    }

    if( !mbedtls_pk_can_do(&privkey_ctx, MBEDTLS_PK_ECKEY) ) {
        ESP_LOGE(TAG, "This not an ECKEY");
        err = -1; goto cleanup;
    }

    ESP_LOGI(TAG, "pbtx_sigp_init() finsihed. Public key:");

    if( (err = mbedtls_pk_write_pubkey_pem( &privkey_ctx, pem_key_buf, PEM_KEY_BUFLEN)) != 0 ) {
            ESP_LOGE(TAG, "mbedtls_pk_write_pubkey_pem returned -0x%04x", (unsigned int) -err );
            goto cleanup;
    }

    printf("%s\n", pem_key_buf);

cleanup:
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
    nvs_close(nvsh);

    return err;
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


/*
  analog of EC_POINT_set_compressed_coordinates() in OpenSSL.
  Code adapted from compression library by Moritz Warning
  https://github.com/mwarning/mbedtls_ecp_compression/blob/master/ecc_point_compression.c
  takes x and y_bit as input
  returns an ECP point in R
*/

static int mbedtls_ecp_set_compressed_coordinates(
    mbedtls_ecp_point *R,
    const mbedtls_ecp_group *grp,
    const mbedtls_mpi *x, int y_bit
) {
    int ret = -1;
    mbedtls_mpi r;
    mbedtls_mpi n;

    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&n);

    // r = x^2
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&r, x, x));

    // r = x^2 + a
    if (grp->A.MBEDTLS_PRIVATE(p) == NULL) {
        // Special case where a is -3
        MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&r, &r, 3));
    } else {
        MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&r, &r, &grp->A));
    }

    // r = x^3 + ax
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&r, &r, x));

    // r = x^3 + ax + b
    MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&r, &r, &grp->B));

    // Calculate square root of r over finite field P:
    //   r = sqrt(x^3 + ax + b) = (x^3 + ax + b) ^ ((P + 1) / 4) (mod P)

    // n = P + 1
    MBEDTLS_MPI_CHK(mbedtls_mpi_add_int(&n, &grp->P, 1));

    // n = (P + 1) / 4
    MBEDTLS_MPI_CHK(mbedtls_mpi_shift_r(&n, 2));

    // r ^ ((P + 1) / 4) (mod p)
    MBEDTLS_MPI_CHK(mbedtls_mpi_exp_mod(&r, &r, &n, &grp->P, NULL));

    // Select solution that has the correct "sign" (equals odd/even solution in finite group)
    if (y_bit != mbedtls_mpi_get_bit(&r, 0)) {
        // r = p - r
        MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&r, &grp->P, &r));
    }

    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&(R->MBEDTLS_PRIVATE(X)), x));
    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&(R->MBEDTLS_PRIVATE(Y)), &r));
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&(R->MBEDTLS_PRIVATE(Z)), 1));
    if( mbedtls_ecp_check_pubkey( grp, R ) != 0 ) {
        ESP_LOGE(TAG, "R does not belong to the group");
    }
    ret = 0;

cleanup:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&n);

    return(ret);
}


/*
 * Given the components of a signature and a selector value, recover
 * and return the public key that generated the signature according to
 * the algorithm in SEC1v2 section 4.1.6.
 *
 * The recId is an index from 0 to 3 which indicates which of the 4
 * possible keys is the correct one. Because the key recovery
 * operation yields multiple potential keys, the correct key must
 * either be stored alongside the signature, or you must be willing to
 * try each recId in turn until you find one that outputs the key you
 * are expecting.
 *
 * If this method returns null it means recovery was not possible and
 * recId should be iterated.
 *
 *
 * Given the above two points, a correct usage of this method is
 * inside a for loop from 0 to 3, and if the output is null OR a key
 * that is not the one you expect, you try again with the next recId.
 */

static int pbtx_sigp_recover_key(int *result, mbedtls_ecp_keypair *ec, mbedtls_mpi *r, mbedtls_mpi *s,
                                 unsigned char *hash, int recid,
                                 int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    int ret;
    *result = 0;

    int i = recid / 2;

    const mbedtls_ecp_group* group = &(ec->MBEDTLS_PRIVATE(grp));
    const mbedtls_mpi* order = &(group->N);

    mbedtls_mpi x; mbedtls_mpi_init(&x);
    mbedtls_mpi e; mbedtls_mpi_init(&e);
    mbedtls_mpi zero; mbedtls_mpi_init(&zero);
    mbedtls_mpi rr; mbedtls_mpi_init(&rr);
    mbedtls_mpi sor; mbedtls_mpi_init(&sor);
    mbedtls_mpi eor; mbedtls_mpi_init(&eor);

    mbedtls_ecp_point R; mbedtls_ecp_point_init(&R);
    mbedtls_ecp_point O; mbedtls_ecp_point_init(&O);
    mbedtls_ecp_point Q; mbedtls_ecp_point_init(&Q);

    mbedtls_ecp_group grpcopy; mbedtls_ecp_group_init( &grpcopy );

    /*  1.0 For j from 0 to h   (h == recId here and the loop is outside this function)
        1.1 Let x = r + jn */
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_int( &x, order, i) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( &x, &x, r ) );

    /*         1.2. Convert the integer x to an octet string X of length mlen using the conversion routine
                    specified in Section 2.3.7, where mlen = [(log2 p)/8] or mlen = [m/8].
               1.3. Convert the octet string (16 set binary digits)||X to an elliptic curve point R using the
                    conversion routine specified in Section 2.3.4. If this conversion routine outputs "invalid", then
                    do another iteration of Step 1.

                    More concisely, what these points mean is to use X as a compressed public key. */

    /* Cannot have point co-ordinates larger than this as everything takes place modulo P. */
    if( mbedtls_mpi_cmp_mpi( &x, &(group->P) ) >= 0 ) { ret = 0; goto cleanup; }

    /*  Compressed keys require you to know an extra bit of data about the y-coord as there are two possibilities.
        So it's encoded in the recId. */
    MBEDTLS_MPI_CHK( mbedtls_ecp_set_compressed_coordinates(&R, group, &x, recid % 2) );

    /* 1.4 check if nR is infinity */
    /* we skip the check because mbedtls_ecp_mul() demands that the multiplier is lower than N */

    /* 1.5. Compute e from M using Steps 2 and 3 of ECDSA signature verification. */
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &e, hash, 32 ) );

    /*
       1.6. For k from 1 to 2 do the following.   (loop is outside this function via iterating recId)
       1.6.1. Compute a candidate public key as:
       Q = mi(r) * (sR - eG)
       Where mi(x) is the modular multiplicative inverse.

       We transform this into the following:
       Q = (mi(r) * s ** R) + (mi(r) * -e ** G)
       Where -e is the modular additive inverse of e, that is z such that z + e = 0 (mod n).
       In the above equation ** is point multiplication and + is point addition (the EC group operator).

       We can find the additive inverse by subtracting e from zero then taking the mod. For example the additive
       inverse of 3 modulo 11 is 8 because 3 + 8 mod 11 = 0, and -3 mod 11 = 8.
    */

    MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &zero, 0 ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mpi( &e, &zero, &e ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( &e, &e, order ) ); // now "e" is -e

    MBEDTLS_MPI_CHK( mbedtls_mpi_inv_mod( &rr, r, order ) ); // rr is mi(r)

    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &sor, &rr, s ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( &sor, &sor, order ) ); // sor = mi(r) * s mod n

    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &eor, &rr, &e ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( &eor, &eor, order ) ); // eor = mi(r) * -e mod n

    /* mbedtls_ecp_mul() needs a non-const group... */
    mbedtls_ecp_group_copy( &grpcopy, group );
    MBEDTLS_MPI_CHK( mbedtls_ecp_muladd(&grpcopy, &Q, &sor, &R, &eor, &(group->G) ) );

    /* compare Q and public key */
    if( mbedtls_ecp_point_cmp( &Q, &(ec->MBEDTLS_PRIVATE(Q)) ) == 0 ) {
        *result = 1;  // they are equal
    }

    ret = 0;

cleanup:
    mbedtls_mpi_free(&x);
    mbedtls_mpi_free(&e);
    mbedtls_mpi_free(&zero);
    mbedtls_mpi_free(&rr);
    mbedtls_mpi_free(&sor);
    mbedtls_mpi_free(&eor);
    mbedtls_ecp_point_free(&R);
    mbedtls_ecp_point_free(&O);
    mbedtls_ecp_point_free(&Q);
    mbedtls_ecp_group_free( &grpcopy );

    return ret;
}


int pbtx_sigp_sign(const unsigned char* data, size_t datalen, unsigned char* sig_buf, size_t buflen, size_t* sig_size)
{
    int ret;

    if( !mbedtls_pk_can_do(&privkey_ctx, MBEDTLS_PK_ECKEY) ) {
        ESP_LOGE(TAG, "Private key is not initialized");
        return -1;
    }

    if( buflen < 66 ) {
        ESP_LOGE(TAG, "Buffer must be at least 66 bytes long");
        return -1;
    }

    mbedtls_entropy_context entropy;  mbedtls_entropy_init( &entropy );
    mbedtls_ctr_drbg_context ctr_drbg; mbedtls_ctr_drbg_init( &ctr_drbg );
    const char *pers = "ecdsa";

    mbedtls_mpi r; mbedtls_mpi_init( &r );
    mbedtls_mpi s; mbedtls_mpi_init( &s );
    mbedtls_mpi halforder;  mbedtls_mpi_init(&halforder);

    MBEDTLS_MPI_CHK( mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                                            (const unsigned char *) pers,
                                            strlen( pers ) ) );

    // compute sha256 of the data
    unsigned char hash[32];
    mbedtls_sha256_context md_ctx;
    mbedtls_sha256_init( &md_ctx );
    mbedtls_sha256_starts( &md_ctx, 0 );
    mbedtls_sha256_update( &md_ctx, data, datalen );
    mbedtls_sha256_finish( &md_ctx, hash );
    mbedtls_sha256_free( &md_ctx );

    mbedtls_ecp_keypair* ec = mbedtls_pk_ec( privkey_ctx );

    MBEDTLS_MPI_CHK( mbedtls_ecdsa_sign( &(ec->MBEDTLS_PRIVATE(grp)), &r, &s, &(ec->MBEDTLS_PRIVATE(d)),
                                         hash, 32,
                                         mbedtls_ctr_drbg_random, &ctr_drbg ));

    /* check and handle low S */

    MBEDTLS_MPI_CHK( mbedtls_mpi_copy(&halforder, &(ec->MBEDTLS_PRIVATE(grp).N)) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_shift_r( &halforder, 1 ) ); // halforder is n/2
    if( mbedtls_mpi_cmp_mpi( &s, &halforder ) > 0 ) {
        MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mpi(&s, &(ec->MBEDTLS_PRIVATE(grp).N), &s) ); // s := n - s
    }

    /* the canonical recovery algorithm goes for i in [0,3]. But secp256r1 has the cofactr h=1,
       so the key is always found for i in [0,1], and higher vaues of i will fail the x<P condition */
    int nRecId = -1;
    for (int i=0; i<2; i++) {
        int result;
        MBEDTLS_MPI_CHK( pbtx_sigp_recover_key(&result, ec, &r, &s, hash, i,
                                               mbedtls_ctr_drbg_random, &ctr_drbg) );
        if( result ) {
            nRecId = i;
            break;
        }
    }

    if (nRecId == -1) {
        ESP_LOGE(TAG, "Unable to construct recoverable key");
        ret = -1;
        goto cleanup;
    }

    *sig_buf = PBTX_KEY_TYPE_ANTELOPE_R1;
    sig_buf++;
    *sig_buf = nRecId+27+4;
    sig_buf++;
    int len = mbedtls_mpi_size( &r );
    mbedtls_mpi_write_binary( &r, sig_buf, len );
    sig_buf += len;
    mbedtls_mpi_write_binary( &s, sig_buf, len);
    *sig_size = 2 + len * 2;

cleanup:
    mbedtls_entropy_free( &entropy );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_mpi_free( &r );
    mbedtls_mpi_free( &s );
    mbedtls_mpi_free( &halforder );
    return ret;
}



static int pbtx_sigp_read_identity(pbtx_identity *id)
{
    int err = 0;

    nvs_handle_t nvsh;
    size_t id_length = 0;
    id->network_id = 0;
    id->actor_id = 0;

    if( (err = nvs_open(STORAGE_NAMESPACE, NVS_READONLY, &nvsh)) != ESP_OK ) {
        ESP_LOGE(TAG, "nvs_open returned %x", err);
        goto cleanup;
    }

    err = nvs_get_blob(nvsh, NVSKEY_IDENTITY, NULL, &id_length);
    if( err == ESP_OK ) {
        if( id_length != sizeof(pbtx_identity) ) {
            ESP_LOGE(TAG, "invalid length %d at %s", id_length, NVSKEY_IDENTITY);
            err = -1; goto cleanup;
        }

        if( (err = nvs_get_blob(nvsh, NVSKEY_IDENTITY, id, &id_length)) != ESP_OK ) {
            ESP_LOGE(TAG, "Cannot read %s from NVS: %x", NVSKEY_IDENTITY, err);
            goto cleanup;
        }
    }

cleanup:
    nvs_close(nvsh);
    return err;
}



int pbtx_sigp_has_identity()
{
    pbtx_identity id;
    pbtx_sigp_read_identity(&id);
    if( id.network_id != 0 && id.actor_id != 0 ) {
        return 1;
    }
    return 0;
}



int pbtx_sigp_gen_actor_id(uint64_t *actor_id)
{
    int err = 0;

    pbtx_identity id;
    pbtx_sigp_read_identity(&id);

    nvs_handle_t nvsh;
    uint8_t macaddr[8];

    if( (err = nvs_open(STORAGE_NAMESPACE, NVS_READWRITE, &nvsh)) != ESP_OK ) {
        ESP_LOGE(TAG, "nvs_open returned %x", err);
        goto cleanup;
    }

    if( id.network_id != 0 ) {
        ESP_LOGE(TAG, "pbtx_sigp_gen_actor_id: tried to overwrite an existing identity");
        err = -1; goto cleanup;
    }

    if( id.actor_id == 0 ) {
        // first try: take MAC address as seed
        if( (err = esp_efuse_mac_get_default(macaddr)) != 0 ) {
            ESP_LOGE(TAG, "esp_efuse_mac_get_default returned error");
            goto cleanup;
        }

        id.actor_id = *((uint64_t *) macaddr);
    }

    // calculate sha256 of previous value and use first 64bit from the hash
    unsigned char hash[32];
    mbedtls_sha256_context md_ctx;
    mbedtls_sha256_init( &md_ctx );
    mbedtls_sha256_starts( &md_ctx, 0 );
    mbedtls_sha256_update( &md_ctx, (uint8_t *)&id.actor_id, sizeof(id.actor_id) );
    mbedtls_sha256_finish( &md_ctx, hash );
    mbedtls_sha256_free( &md_ctx );

    id.actor_id = *((uint64_t *) hash) & 0x7FFFFFFFFFFFFFFF;

    if( (err = nvs_set_blob(nvsh, NVSKEY_IDENTITY, &id, sizeof(id))) != ESP_OK ) {
        ESP_LOGE(TAG, "Cannot write %s to NVS: %x", NVSKEY_IDENTITY, err);
        goto cleanup;
    }

    if( (err =  nvs_commit(nvsh)) != ESP_OK ) {
        ESP_LOGE(TAG, "nvs_commit returned %x", err);
        goto cleanup;
    }

    *actor_id = id.actor_id;

cleanup:
    nvs_close(nvsh);
    return err;
}


int pbtx_sigp_read_actor_id(uint64_t *actor_id)
{
    pbtx_identity id;
    if( pbtx_sigp_read_identity(&id) != 0 ) {
        *actor_id = 0;
        return -1;
    }

    *actor_id = id.actor_id;
    return 0;
}




int pbtx_sigp_save_last_rpc_msghash(const unsigned char* data, size_t datalen)
{
    int err = 0;
    nvs_handle_t nvsh;

    unsigned char hash[32];
    mbedtls_sha256_context md_ctx;
    mbedtls_sha256_init( &md_ctx );
    mbedtls_sha256_starts( &md_ctx, 0 );
    mbedtls_sha256_update( &md_ctx, data, datalen );
    mbedtls_sha256_finish( &md_ctx, hash );
    mbedtls_sha256_free( &md_ctx );

    if( (err = nvs_open(STORAGE_NAMESPACE, NVS_READWRITE, &nvsh)) != ESP_OK ) {
        ESP_LOGE(TAG, "nvs_open returned %x", err);
        goto cleanup;
    }

    if( (err = nvs_set_blob(nvsh, NVSKEY_RPC_MSGHASH, hash, 32)) != ESP_OK ) {
        ESP_LOGE(TAG, "Cannot write %s to NVS: %x", NVSKEY_RPC_MSGHASH, err);
        goto cleanup;
    }

cleanup:
    nvs_close(nvsh);
    return err;
}



int pbtx_sigp_check_last_rpc_msghash(unsigned char* hash, size_t hashlen)
{
    int err = -1;
    nvs_handle_t nvsh;

    if( (err = nvs_open(STORAGE_NAMESPACE, NVS_READWRITE, &nvsh)) != ESP_OK ) {
        ESP_LOGE(TAG, "nvs_open returned %x", err);
        goto cleanup;
    }

    if( hashlen != 32 ) {
        ESP_LOGE(TAG, "Wrong hashlen: %d. Expected 32", hashlen);
        goto cleanup;
    }

    if( (err = nvs_open(STORAGE_NAMESPACE, NVS_READONLY, &nvsh)) != ESP_OK ) {
        ESP_LOGE(TAG, "nvs_open returned %x", err);
        goto cleanup;
    }

    unsigned char saved_hash[32];
    size_t saved_hash_len;
    err = nvs_get_blob(nvsh, NVSKEY_RPC_MSGHASH, NULL, &saved_hash_len);
    if( err == ESP_OK ) {
        if( saved_hash_len != 32 ) {
            ESP_LOGE(TAG, "pbtx_sigp_get_last_rpc_msghash wrong size on NVS : %d bytes, need 32 bytes", saved_hash_len);
            goto cleanup;
        }

        if( (err = nvs_get_blob(nvsh, NVSKEY_RPC_MSGHASH, saved_hash, &saved_hash_len)) != ESP_OK ) {
            ESP_LOGE(TAG, "Cannot read %s from NVS: %x", NVSKEY_IDENTITY, err);
            goto cleanup;
        }

        if( memcmp(hash, saved_hash, 32) != 0 ) {
            ESP_LOGE(TAG, "The hash does not match the previous message");
            err = 1; goto cleanup;
        }

        err = 0;
    }
    else if( err == ESP_ERR_NVS_NOT_FOUND ) {
        ESP_LOGI(TAG, "No msghash on NVS");
        goto cleanup;
    }

cleanup:
    nvs_close(nvsh);
    return err;
}


int pbtx_sigp_upd_network(uint64_t network_id, uint32_t last_seqnum, uint64_t prev_hash)
{
    int err = 0;
    nvs_handle_t nvsh;

    pbtx_seq seq;
    seq.last_seqnum = last_seqnum;
    seq.prev_hash = prev_hash;

    pbtx_identity id;
    pbtx_sigp_read_identity(&id);
    if( id.network_id != 0 ) {
        ESP_LOGE(TAG, "pbtx_sigp_upd_network: cannot overwrite an existing identity");
        return -1;
    }

    id.network_id = network_id;

    if( (err = nvs_open(STORAGE_NAMESPACE, NVS_READWRITE, &nvsh)) != ESP_OK ) {
        ESP_LOGE(TAG, "nvs_open returned %x", err);
        goto cleanup;
    }

    if( (err = nvs_set_blob(nvsh, NVSKEY_IDENTITY, &id, sizeof(id))) != ESP_OK ) {
        ESP_LOGE(TAG, "Cannot write %s to NVS: %x", NVSKEY_IDENTITY, err);
        goto cleanup;
    }

    if( (err = nvs_set_blob(nvsh, NVSKEY_SEQ, &seq, sizeof(seq))) != ESP_OK ) {
        ESP_LOGE(TAG, "Cannot write %s to NVS: %x", NVSKEY_SEQ, err);
        goto cleanup;
    }

    if( (err =  nvs_commit(nvsh)) != ESP_OK ) {
        ESP_LOGE(TAG, "nvs_commit returned %x", err);
        goto cleanup;
    }

cleanup:
    nvs_close(nvsh);
    return err;
}


int pbtx_sigp_get_identity(uint64_t *network_id, uint64_t *actor_id, uint32_t *last_seqnum, uint64_t *prev_hash)
{
    int err = 0;
    nvs_handle_t nvsh;

    if( (err = nvs_open(STORAGE_NAMESPACE, NVS_READWRITE, &nvsh)) != ESP_OK ) {
        ESP_LOGE(TAG, "nvs_open returned %x", err);
        goto cleanup;
    }

    pbtx_identity id;
    pbtx_sigp_read_identity(&id);
    if( id.network_id == 0 || id.actor_id == 0 ) {
        ESP_LOGE(TAG, "pbtx_sigp_get_identity called, but identity does not exist");
        return -1;
    }

    *network_id = id.network_id;
    *actor_id = id.actor_id;

    if( last_seqnum != NULL && prev_hash != NULL ) {
        pbtx_seq seq;
        size_t seq_length;
        err = nvs_get_blob(nvsh, NVSKEY_SEQ, NULL, &seq_length);
        if( err == ESP_OK ) {
            if( seq_length != sizeof(pbtx_seq) ) {
                ESP_LOGE(TAG, "invalid length %d at %s", seq_length, NVSKEY_SEQ);
                err = -1; goto cleanup;
            }

            if( (err = nvs_get_blob(nvsh, NVSKEY_IDENTITY, &seq, &seq_length)) != ESP_OK ) {
                ESP_LOGE(TAG, "Cannot read %s from NVS: %x", NVSKEY_SEQ, err);
                goto cleanup;
            }

            *last_seqnum = seq.last_seqnum;
            *prev_hash = seq.prev_hash;
        }
    }

cleanup:
    nvs_close(nvsh);
    return err;
}



int pbtx_sigp_upd_seq(uint32_t last_seqnum, uint64_t prev_hash)
{
    int err = 0;
    nvs_handle_t nvsh;

    pbtx_seq seq;
    seq.last_seqnum = last_seqnum;
    seq.prev_hash = prev_hash;

    if( (err = nvs_open(STORAGE_NAMESPACE, NVS_READWRITE, &nvsh)) != ESP_OK ) {
        ESP_LOGE(TAG, "nvs_open returned %x", err);
        goto cleanup;
    }

    if( (err = nvs_set_blob(nvsh, NVSKEY_SEQ, &seq, sizeof(seq))) != ESP_OK ) {
        ESP_LOGE(TAG, "Cannot write %s to NVS: %x", NVSKEY_SEQ, err);
        goto cleanup;
    }

    if( (err =  nvs_commit(nvsh)) != ESP_OK ) {
        ESP_LOGE(TAG, "nvs_commit returned %x", err);
        goto cleanup;
    }

cleanup:
    nvs_close(nvsh);
    return err;
}


uint64_t pbtx_sigp_calc_prevhash(const unsigned char* body, size_t bodylen)
{
    unsigned char hash[32];
    mbedtls_sha256_context md_ctx;
    mbedtls_sha256_init( &md_ctx );
    mbedtls_sha256_starts( &md_ctx, 0 );
    mbedtls_sha256_update( &md_ctx, body, bodylen );
    mbedtls_sha256_finish( &md_ctx, hash );
    mbedtls_sha256_free( &md_ctx );

    uint64_t body_hash = 0;
    for( uint32_t i = 0; i < 8; i++ ) {
        body_hash = (body_hash << 8) | hash[i];
    }

    return body_hash;
}


int pbtx_sigp_erase_identity()
{
    int err = 0;
    nvs_handle_t nvsh;

    if( (err = nvs_open(STORAGE_NAMESPACE, NVS_READWRITE, &nvsh)) != ESP_OK ) {
        ESP_LOGE(TAG, "nvs_open returned %x", err);
        goto cleanup;
    }

    err = nvs_erase_key(nvsh, NVSKEY_IDENTITY);
    if( err != ESP_OK && err != ESP_ERR_NVS_NOT_FOUND ) {
        ESP_LOGE(TAG, "Cannot erase %s from NVS: %x", NVSKEY_IDENTITY, err);
        goto cleanup;
    }

    err = nvs_erase_key(nvsh, NVSKEY_SEQ);
    if( err != ESP_OK && err != ESP_ERR_NVS_NOT_FOUND ) {
        ESP_LOGE(TAG, "Cannot erase %s from NVS: %x", NVSKEY_SEQ, err);
        goto cleanup;
    }

    err = 0;
cleanup:
    nvs_close(nvsh);
    return err;
}
