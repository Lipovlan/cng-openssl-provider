#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include "cng_signature_functions.h"
#include <ntstatus.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include "../../debug.h"

#define DEBUG_LEVEL DEBUG_ERROR

/**
 * Create new signature context
 * this should allow simultaneous signature operations.
 *
 * [1] https://www.openssl.org/docs/man3.0/man7/property.html
 * @param provctx Providers context
 * @param propq Property query as in [1]
 * @return Pointer to the newly allocated signature context
 */
void *cng_signature_newctx(void *provctx, const char *propq) {
    debug_printf("SIGNATURE> cng_signature_newctx\n", DEBUG_TRACE, DEBUG_LEVEL);
    T_CNG_SIGNATURE_CTX *sig_ctx = malloc(sizeof(T_CNG_SIGNATURE_CTX));
    if (sig_ctx == NULL){ return NULL; }
    sig_ctx->hash_handle = NULL;
    sig_ctx->alg_identifier = NULL;
    sig_ctx->key = NULL;
    sig_ctx->propq = propq;
    sig_ctx->provctx = provctx;
    sig_ctx->sign_hash_flags = 0;
    sig_ctx->pss_salt_len = 0;
    return sig_ctx;
}

/**
 * Duplicate signature context
 * @param ctx Old context
 * @return New context or NULL on error
 */
void *cng_signature_dupctx(void *ctx) {
    debug_printf("SIGNATURE> cng_signature_dupctx\n", DEBUG_TRACE, DEBUG_LEVEL);
    T_CNG_SIGNATURE_CTX *old_sig_ctx = ctx;
    T_CNG_SIGNATURE_CTX *new_sig_ctx = cng_signature_newctx(old_sig_ctx->provctx, old_sig_ctx->propq);

    /* Copy hash handle */
    NTSTATUS s = BCryptDuplicateHash(old_sig_ctx->hash_handle, &new_sig_ctx->hash_handle, NULL, 0, 0);
    if (s != STATUS_SUCCESS) { return NULL; }

    /* Copy Algorithm provider */
    new_sig_ctx->alg_identifier = old_sig_ctx->alg_identifier;

    /* Copy key data */
    new_sig_ctx->key = cng_keymgmt_dup(old_sig_ctx->key, OSSL_KEYMGMT_SELECT_ALL);
    if (old_sig_ctx->key != NULL && new_sig_ctx->key == NULL) { return NULL; }

    /* Copy information for BCryptSignHash */
    new_sig_ctx->sign_hash_flags = old_sig_ctx->sign_hash_flags;
    new_sig_ctx->pss_salt_len = old_sig_ctx->pss_salt_len;

    return new_sig_ctx;
}

/**
 * Destroy signature context
 * @param ctx Signature context to ber freed
 */
void cng_signature_freectx(void *ctx) {
    debug_printf("SIGNATURE> cng_signature_freectx\n", DEBUG_TRACE, DEBUG_LEVEL);
    T_CNG_SIGNATURE_CTX *sig_ctx = ctx;
    BCryptDestroyHash(sig_ctx->hash_handle);
    free(sig_ctx);
}

/**
 * Helper function to translate OpenSSL digest names to BCrypt digest names
 * @param ossl_mdname OpenSSL digest name
 * @param bcrypt_mdname BCrypt digest name
 * @return Whether the conversion was a success (0 on error)
 */
int
ossl_digest_name_to_bcrypt_digest_name(T_CNG_SIGNATURE_CTX *sig_ctx, const char *ossl_mdname, LPCWSTR *bcrypt_mdname) {
    /* Here we have to translate OpenSSL hash names to CNG hash names
    * https://learn.microsoft.com/en-us/windows/win32/seccng/cng-algorithm-identifiers
    * https://www.openssl.org/docs/man3.0/man3/SSL_CTX_set1_sigalgs.html
    * https://www.openssl.org/docs/man3.0/man3/EVP_MD_CTX_new.html
    */
    if (sig_ctx == NULL || ossl_mdname == NULL || bcrypt_mdname == NULL) { return 0; }
    *bcrypt_mdname = 0x00;
    const EVP_MD *md = EVP_MD_fetch(NULL, ossl_mdname, NULL);
    if (md == NULL) { return 0; }

    if (EVP_MD_is_a(md, OSSL_DIGEST_NAME_SHA2_256)) { *bcrypt_mdname = BCRYPT_SHA256_ALGORITHM; }
    if (EVP_MD_is_a(md, OSSL_DIGEST_NAME_SHA2_384)) { *bcrypt_mdname = BCRYPT_SHA384_ALGORITHM; }
    if (EVP_MD_is_a(md, OSSL_DIGEST_NAME_SHA2_512)) { *bcrypt_mdname = BCRYPT_SHA512_ALGORITHM; }

    return *bcrypt_mdname != 0x00;
}

/**
 * Initialize the signature
 * @param ctx Signature context
 * @param mdname Digest name
 * @param provkey Provider side key object
 * @param params Parameters of the signature
 * @return One on success, zero on failure
 */
int cng_signature_digest_sign_init(void *ctx, const char *mdname,
                                   void *provkey,
                                   const OSSL_PARAM params[]) {
    debug_printf("SIGNATURE> cng_signature_digest_sign_init\n", DEBUG_TRACE, DEBUG_LEVEL);
    T_CNG_SIGNATURE_CTX *sig_ctx = (T_CNG_SIGNATURE_CTX *) ctx;
    sig_ctx->key = provkey;

    if (!ossl_digest_name_to_bcrypt_digest_name(sig_ctx, mdname, &sig_ctx->alg_identifier)) {
        debug_printf("SIGN> Unsupported hashing algorithm\n", DEBUG_TRACE, DEBUG_LEVEL);
        return 0;
    }

    BCRYPT_ALG_HANDLE alg_prov_handle;
    NTSTATUS s = BCryptOpenAlgorithmProvider(&alg_prov_handle, sig_ctx->alg_identifier, NULL, 0);
    if (s != STATUS_SUCCESS) { return 0; }

    s = BCryptCreateHash(alg_prov_handle, &sig_ctx->hash_handle, NULL, 0, NULL, 0, 0);

    BCryptCloseAlgorithmProvider(alg_prov_handle, 0);
    return s == STATUS_SUCCESS;
}

/**
 * Update the signature
 *
 * Can be called multiple times, should cumulate the data being passed to it
 * @param ctx Signature context
 * @param data Data for signature
 * @param datalen Length of data parameter
 * @return One on success, zero on failure
 */
int cng_signature_digest_sign_update(void *ctx,
                                     const unsigned char *data,
                                     size_t datalen) {
    debug_printf("SIGNATURE> cng_signature_digest_sign_update\n", DEBUG_TRACE, DEBUG_LEVEL);
    T_CNG_SIGNATURE_CTX *sig_ctx = (T_CNG_SIGNATURE_CTX *) ctx;
    /* Documentation states that pbInput will not be modified
     * https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcrypthashdata */
    NTSTATUS s = BCryptHashData(sig_ctx->hash_handle, data, datalen, 0);
    return s == STATUS_SUCCESS;
}

/**
 * Finish the signature
 * @param ctx Signature context
 * @param sig Output buffer for the signature
 * @param siglen Length of sig parameter buffer
 * @return One on success, zero on failure
 */
int cng_signature_digest_sign_final(void *ctx, unsigned char *sig,
                                    size_t *siglen, size_t sigsize) {
    debug_printf("SIGNATURE> cng_signature_digest_sign_final\n", DEBUG_TRACE, DEBUG_LEVEL);
    T_CNG_SIGNATURE_CTX *sig_ctx = (T_CNG_SIGNATURE_CTX *) ctx;
    ULONG pcb_result;
    void *padding_info;
    NTSTATUS s;
    SECURITY_STATUS ss;

    /* Check hash size */
    DWORD hash_length;
    s = BCryptGetProperty(sig_ctx->hash_handle, BCRYPT_HASH_LENGTH, (PUCHAR) &hash_length, sizeof(hash_length),
                          &pcb_result, 0);
    if (s != STATUS_SUCCESS) { return 0; }

    if (sig == NULL) {
        /* Caller wants to know how much memory he needs to allocate */
        unsigned char *hash_placeholder = malloc(hash_length);
        if (hash_placeholder == NULL) { return 0; }
        ss = NCryptSignHash(sig_ctx->key->windows_key_handle, NULL, hash_placeholder, hash_length, NULL, 0,
                            (DWORD *) siglen, 0);
        if (ss != ERROR_SUCCESS) {
            free(hash_placeholder);
            return 0;
        }
        free(hash_placeholder);
        return 1;
    } else {
        /* Allocate buffer for finalised hash */
        unsigned char *hash_buffer = malloc(hash_length);
        if (hash_buffer == NULL) { return 0; }
        /* Finalize hash */
        s = BCryptFinishHash(sig_ctx->hash_handle, hash_buffer, hash_length, 0);
        if (s != STATUS_SUCCESS) {
            free(hash_buffer);
            return 0;
        }

        /* Set correct padding */
        if (sig_ctx->sign_hash_flags == BCRYPT_PAD_PSS) {
            BCRYPT_PSS_PADDING_INFO *p = malloc(sizeof(BCRYPT_PSS_PADDING_INFO));
            if (p == NULL){ return 0; }
            p->pszAlgId = sig_ctx->alg_identifier;
            p->cbSalt = sig_ctx->pss_salt_len;
            padding_info = p;
        } else if (sig_ctx->sign_hash_flags == BCRYPT_PAD_PKCS1) {
            BCRYPT_PKCS1_PADDING_INFO *p = malloc(sizeof(BCRYPT_PKCS1_PADDING_INFO));
            if (p == NULL){ return 0; }
            p->pszAlgId = sig_ctx->alg_identifier;
            padding_info = p;
        } else {
            debug_printf("SIGN> Unknown padding recevied!\n", DEBUG_ERROR, DEBUG_LEVEL);
            free(hash_buffer);
            return 0;
        }

        /* Sign the hash */
        ss = NCryptSignHash(sig_ctx->key->windows_key_handle, padding_info, hash_buffer, hash_length, sig, sigsize,
                            (DWORD *) siglen, sig_ctx->sign_hash_flags);

        free(padding_info);
        free(hash_buffer);
        return (ss == ERROR_SUCCESS);
    }
}

/* Mandatory values for settable for RSA can be found here:
 * https://www.openssl.org/docs/man3.0/man7/EVP_SIGNATURE-RSA.html */
const OSSL_PARAM *cng_signature_settable_ctx_params(void *ctx, void *provctx) {
    static OSSL_PARAM settable[] = {
            OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
            OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PROPERTIES, NULL, 0),
            OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
            OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, NULL, 0),
            OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_PROPERTIES, NULL, 0),
            OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL, 0),
            OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL),
            OSSL_PARAM_END
    };
    return settable;
}

/**
 * Set signature context parameters
 * @param ctx Signature context
 * @param params Parameters to be set
 * @return One on success, zero on error
 */
int cng_signature_set_ctx_params(void *ctx, const OSSL_PARAM params[]) {
    const OSSL_PARAM *p;
    T_CNG_SIGNATURE_CTX *sig_ctx = ctx;
    NTSTATUS s;
    int param_set = 0;

    /* Check padding mode */
    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PAD_MODE);
    if (p != NULL) {
        /* https://www.openssl.org/docs/man3.0/man7/EVP_ASYM_CIPHER-RSA.html
         * https://www.openssl.org/docs/man3.0/man3/EVP_PKEY_CTX_set_rsa_padding.html */
        if (p->data_type == OSSL_PARAM_INTEGER) {
            if (*(int *) p->data == RSA_PKCS1_PSS_PADDING) {
                sig_ctx->sign_hash_flags = BCRYPT_PAD_PSS;
            } else if (*(int *) p->data == RSA_PKCS1_PADDING) {
                sig_ctx->sign_hash_flags = BCRYPT_PAD_PKCS1;
            } else {
                debug_printf("SIGN> Unknown padding mode requested as integer!\n", DEBUG_ERROR, DEBUG_LEVEL);
                return 0;
            }
        } else if (p->data_type == OSSL_PARAM_UTF8_STRING) {
            if (!strcmp(p->data, OSSL_PKEY_RSA_PAD_MODE_PSS)) {

            } else if (!strcmp(p->data, OSSL_PKEY_RSA_PAD_MODE_PKCSV15)) {
                sig_ctx->sign_hash_flags = BCRYPT_PAD_PKCS1;
            } else {
                debug_printf("SIGN> Unknown padding mode requested as string!\n", DEBUG_ERROR, DEBUG_LEVEL);
                return 0;
            }
        } else {
            debug_printf("SIGN> Padding mode requested in unexpected data type!\n", DEBUG_ERROR, DEBUG_LEVEL);
            return 0;
        }
        param_set = 1;
    }

    /* Check PSS Salt length */
    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PSS_SALTLEN);
    if (p != NULL) {
        if (p->data_type == OSSL_PARAM_INTEGER) {
            /* Explicit salt length received, just use its value */
            sig_ctx->pss_salt_len = *(ULONG *) p->data;
        } else if (p->data_type == OSSL_PARAM_UTF8_STRING) {
            /* Received special property, decode it */
            if (!strcmp(p->data, OSSL_PKEY_RSA_PSS_SALT_LEN_DIGEST)) {
                ULONG receivedBytes;
                s = BCryptGetProperty(sig_ctx->hash_handle, BCRYPT_HASH_LENGTH, (PUCHAR) &sig_ctx->pss_salt_len,
                                      sizeof(sig_ctx->pss_salt_len), &receivedBytes, 0);
                if (s != STATUS_SUCCESS || receivedBytes == 0) {
                    sig_ctx->pss_salt_len = 0;
                    return 0;
                }
            } else if (!strcmp(p->data, OSSL_PKEY_RSA_PSS_SALT_LEN_MAX)) {
                debug_printf("SIGN> Max salt length detection not implemented!\n", DEBUG_ERROR, DEBUG_LEVEL);
                return 0;
            } else if (!strcmp(p->data, OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO)) {
                debug_printf("SIGN> Automatic salt length detection not implemented!\n", DEBUG_ERROR, DEBUG_LEVEL);
                return 0;
            } else {
                return 0;
            }
        } else {
            debug_printf("SIGN> Salt length received in unknown data type!\n", DEBUG_ERROR, DEBUG_LEVEL);
            return 0;
        }
        param_set = 1;
    }
    if (!param_set) {
        debug_printf("SIGN> Setting unknown parameter!\n", DEBUG_ERROR, DEBUG_LEVEL);
        return 0;
    }
    return 1;
}

/* Functions we provide to the OpenSSL libraries */
const OSSL_DISPATCH cng_signature_functions[] = {
        {OSSL_FUNC_SIGNATURE_NEWCTX,              (void (*)(void)) cng_signature_newctx},
        {OSSL_FUNC_SIGNATURE_DUPCTX,              (void (*)(void)) cng_signature_dupctx},
        {OSSL_FUNC_SIGNATURE_FREECTX,             (void (*)(void)) cng_signature_freectx},
        {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,    (void (*)(void)) cng_signature_digest_sign_init},
        {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,  (void (*)(void)) cng_signature_digest_sign_update},
        {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,   (void (*)(void)) cng_signature_digest_sign_final},
        {OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,      (void (*)(void)) cng_signature_set_ctx_params},
        {OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void (*)(void)) cng_signature_settable_ctx_params},
        {0, NULL}
};