#pragma once

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <windows.h>
#include <wincrypt.h>
#include <ncrypt.h>
#include "../cng_provider.h"
#include "../keymgmt/cng_keymgmt_functions.h"

/* Our providers signature context */
typedef struct s_cng_signature_ctx {
    /* Pointer to our providers context */
    T_CNG_PROVIDER_CTX *provctx;
    /* Property query for when we can choose implementations and so on */
    const char *propq;
    /* Windows algorithm identifier, a unicode string */
    LPCWSTR alg_identifier;
    /* Pointer to our providers key object for signing */
    T_CNG_KEYMGMT_KEYDATA *key;
    /* Windows handle for a hash */
    BCRYPT_HASH_HANDLE hash_handle;
    /* Windows flags for a signature hash */
    ULONG sign_hash_flags;
    /* Windows hash PSS salt length */
    ULONG pss_salt_len;
} T_CNG_SIGNATURE_CTX;

/* Basic functions for creating, cloning and destroying the signature context */
OSSL_FUNC_signature_newctx_fn cng_signature_newctx;
OSSL_FUNC_signature_dupctx_fn cng_signature_dupctx;
OSSL_FUNC_signature_freectx_fn cng_signature_freectx;

/* Function so signing a digest of data works */
OSSL_FUNC_signature_digest_sign_init_fn cng_signature_digest_sign_init;
OSSL_FUNC_signature_digest_sign_update_fn cng_signature_digest_sign_update;
OSSL_FUNC_signature_digest_sign_final_fn cng_signature_digest_sign_final;
/* Possible one-shot implementation of the above sign digest functions */
//OSSL_FUNC_signature_digest_sign_fn cng_signature_digest_sign;

OSSL_FUNC_signature_set_ctx_params_fn cng_signature_set_ctx_params;
OSSL_FUNC_signature_settable_ctx_params_fn cng_signature_settable_ctx_params;

/*Ideally things above are the minimum for sending client certificate
 * Things below should be implemented in groups */

/* Functions for signing, _sign_init() initializes the context for the actual signature by _sign() */
//OSSL_FUNC_signature_sign_init_fn cng_signature_sign_init;
//OSSL_FUNC_signature_sign_fn cng_signature_sign;

/* Functions for verifying signatures, similar to functions above */
//OSSL_FUNC_signature_verify_init_fn cng_signature_verify_init;
//OSSL_FUNC_signature_verify_fn cng_signature_verify;

/* Functions for message recovery from a signature, again one for init, and one for the actual recovery */
//OSSL_FUNC_signature_verify_recover_init_fn cng_signature_verify_recover_init;
//OSSL_FUNC_signature_verify_recover_fn cng_signature_verify_recover;

/* Functions to verify a digest signature, similar to digest signing functions */
//OSSL_FUNC_signature_digest_verify_init_fn cng_signature_digest_verify_init;
//OSSL_FUNC_signature_digest_verify_update_fn cng_signature_digest_verify_update;
//OSSL_FUNC_signature_digest_verify_final_fn cng_signature_digest_verify_final;
/* One shot function for the above */
//OSSL_FUNC_signature_digest_verify_fn cng_signature_digest_verify;

/* This function is used by OpenSSL to get type information about the current signature
 * for example the padding type */
//OSSL_FUNC_signature_get_ctx_params_fn cng_signature_get_ctx_params;
/* This should return an array of parameter that get_params() can output */
//OSSL_FUNC_signature_gettable_ctx_params_fn cng_signature_gettable_ctx_params;

/* These functions get and set in a similar manner to previous functions information about
 * message digest functions associated with given signature */
//OSSL_FUNC_signature_get_ctx_md_params_fn cng_signature_get_ctx_md_params;
//OSSL_FUNC_signature_gettable_ctx_md_params_fn cng_signature_gettable_ctx_md_params;
//OSSL_FUNC_signature_set_ctx_md_params_fn cng_signature_set_ctx_md_params;
//OSSL_FUNC_signature_settable_ctx_md_params_fn cng_signature_settable_ctx_md_params;

const OSSL_DISPATCH cng_signature_functions[9];
static const OSSL_ALGORITHM cng_signature[] = {
        /*
         * The structure is as follows:
         * [Names by which OpenSSL fetches this implementation separated by colon],
         * [properties of this as in https://www.openssl.org/docs/manmaster/man7/property.html],
         * [actual function pointers], [optional description]
         */
        {"RSA:rsaEncryption", CNG_DEFAULT_ALG_PROPERTIES, cng_signature_functions, "CNG RSA signature functions"},
        /* Other algorithm names include (but are not limited to) ED25519, ED448, EC:id-ecPublicKey, DSA, X25519 */
        {NULL, NULL, NULL}
};