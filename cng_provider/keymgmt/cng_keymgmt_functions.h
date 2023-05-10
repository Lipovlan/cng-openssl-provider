#pragma once

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <windows.h>
#include <wincrypt.h>
#include <ncrypt.h>
#include "../cng_provider.h"
#include "../../debug.h"

/* The primary responsibility of the KEYMGMT module is to hold the provider side key data for
 * the OpenSSL library EVP_PKEY structure.
 * - https://www.openssl.org/docs/man3.1/man7/provider-keymgmt.html */

/* Basic function to create, copy and destroy provider side key objects */
OSSL_FUNC_keymgmt_new_fn cng_keymgmt_new;
OSSL_FUNC_keymgmt_dup_fn cng_keymgmt_dup;
OSSL_FUNC_keymgmt_free_fn cng_keymgmt_free;

/* Create provider side key object from data received from another provider module (like storemgmt) */
OSSL_FUNC_keymgmt_load_fn cng_keymgmt_load;

/* This function is used by OpenSSL to get type information about the current key
 * for example how many bits it's the modulus has */
OSSL_FUNC_keymgmt_get_params_fn cng_keymgmt_get_params;
/* Although gettable_params was not called during testing, the documentation mandates, that
 * the existence of get_params implies the existence of gettable_params.
 * It should return an array of parameter that get_params() can output */
OSSL_FUNC_keymgmt_gettable_params_fn cng_keymgmt_gettable_params;
/* Similar to get_params but answers questions about data subsets, for example if the key contains its private part */
OSSL_FUNC_keymgmt_has_fn cng_keymgmt_has;

/* For exporting public parts of (or even whole) keys to OpenSSL format */
OSSL_FUNC_keymgmt_export_fn cng_keymgmt_export;

//Things below did not get called during development of the provider in our scenario
/* Match function is usually only needed when your provider does not allow exporting keys.
 * OpenSSL can export the private part of your key and check it itself against another. And since
 * equal public keys should mean equal private keys it is most of the time sufficient */
//OSSL_FUNC_keymgmt_match_fn cng_keymgmt_match;
/* This function should validate the key object passed to it. */
//OSSL_FUNC_keymgmt_validate_fn cng_keymgmt_validate;

/* Return parameters that export() callback can receive, not actually called during testing.
 * Only needed for providers compatible with OpenSSL from 3.0.0 to 3.2.0 excluded. In 3.2.0
 * this has been superseded by export_types_ex()
 * Either this or its _ex variant is mandatory by https://www.openssl.org/docs/manmaster/man7/provider-keymgmt.html */
OSSL_FUNC_keymgmt_export_types_fn cng_keymgmt_export_types;

/* The same thing as export_types(), but for OpenSSL 3.2.0+ */
OSSL_FUNC_keymgmt_export_types_ex_fn cng_keymgmt_export_types_ex;

/* This function is purely advisory and optional */
//OSSL_FUNC_keymgmt_query_operation_name_fn cng_keymgmt_query_operation_name;

/* These functions are needed when implementing key generation */
//OSSL_FUNC_keymgmt_gen_init_fn cng_keymgmt_gen_init;
//OSSL_FUNC_keymgmt_gen_set_template_fn cng_keymgmt_gen_set_template;
//OSSL_FUNC_keymgmt_gen_set_params_fn cng_keymgmt_gen_set_params;
//OSSL_FUNC_keymgmt_gen_settable_params_fn cng_keymgmt_gen_settable_params;
//OSSL_FUNC_keymgmt_gen_fn cng_keymgmt_gen;
//OSSL_FUNC_keymgmt_gen_cleanup_fn cng_keymgmt_gen_cleanup;

/* These functions are needed when you want to import keys from other providers or OpenSSL to your provider */
//OSSL_FUNC_keymgmt_import_fn cng_keymgmt_import;
//OSSL_FUNC_keymgmt_import_types_fn cng_keymgmt_import_types;

/* Our provider side key object data type */
typedef struct s_cng_keymgmt_keydata {
    NCRYPT_KEY_HANDLE windows_key_handle;
} T_CNG_KEYMGMT_KEYDATA;

const OSSL_DISPATCH cng_keymgmt_functions[11];

/** Parameters we can provide through keymgmt_get_params() */
static const OSSL_PARAM cng_keymgmt_param_types[] = {
        OSSL_PARAM_DEFN(OSSL_PKEY_PARAM_BITS, OSSL_PARAM_INTEGER, NULL, 0),
        OSSL_PARAM_DEFN(OSSL_PKEY_PARAM_SECURITY_BITS, OSSL_PARAM_INTEGER, NULL, 0),
        OSSL_PARAM_DEFN(OSSL_PKEY_PARAM_MAX_SIZE, OSSL_PARAM_INTEGER, NULL, 0),
        OSSL_PARAM_END
};

static const OSSL_ALGORITHM cng_keymgmt[] = {
        /*
         * The structure is as follows:
         * [Names by which OpenSSL fetches this implementation separated by colon],
         * [properties of this as in https://www.openssl.org/docs/manmaster/man7/property.html],
         * [actual function pointers], [optional description]
         */
        {"rsaEncryption", CNG_DEFAULT_ALG_PROPERTIES,
                cng_keymgmt_functions, "CNG Provider RSA Implementation"},
        /* Other algorithm names include (but are not limited to) ED25519, ED448, EC:id-ecPublicKey, DSA, X25519 */
        {NULL, NULL, NULL}
};