#pragma once

#include <string.h>
#include <openssl/core_object.h>
#include <openssl/core_names.h>
#include <openssl/x509.h>
#include <openssl/store.h>
#include <windows.h>
#include <wincrypt.h>
#include <ncrypt.h>
#include "../cng_provider.h"
#include "../keymgmt/cng_keymgmt_functions.h"

/*Basic store functions */
OSSL_FUNC_store_open_fn cng_store_open;
//OSSL_FUNC_store_attach_fn cng_store_attach;
OSSL_FUNC_store_load_fn cng_store_load;
OSSL_FUNC_store_close_fn cng_store_close;
OSSL_FUNC_store_eof_fn cng_store_eof;

/* For letting core set parameters of our store */
OSSL_FUNC_store_settable_ctx_params_fn cng_store_settable_ctx_params;
OSSL_FUNC_store_set_ctx_params_fn cng_store_set_ctx_params;

/* For supported types export from our provider back to OpenSSL core */
//OSSL_FUNC_store_export_object_fn cng_store_export_object;

const OSSL_DISPATCH cng_store_functions[9];

static const OSSL_ALGORITHM cng_store[] = {
        {"cng", CNG_DEFAULT_ALG_PROPERTIES, cng_store_functions, "CNG Provider Implementation"},
        {NULL, NULL, NULL}
};

/* Our custom providers store context */
typedef struct cng_store_ctx {
    /* To allow for faster response when fetching parameters */
    int expected_parameter_type;

    /* Windows certificate store handle */
    HCERTSTORE windows_certificate_store;
    /* Last certificate loaded from the Windows certificate store */
    PCCERT_CONTEXT prev_cert_ctx;
    /* Current EOF state of our certificate store */
    int cert_store_eof;

    /* Last private key loaded from the Windows key storage provider */
    PCCERT_CONTEXT prev_key_cert_ctx;
    /* Last private key in our providers format */
    T_CNG_KEYMGMT_KEYDATA * key;
    /* Current EOF state of our keys storage provider */
    int priv_key_store_eof;

    /* Parameters that the OpenSSL core requested */
    char *propquery;

    const char * windows_system_store_name;

    /* e.g.CERT_SYSTEM_STORE_CURRENT_USER or CERT_SYSTEM_STORE_LOCAL_MACHINE */ 
    DWORD store_location_flag; 
} T_CNG_STORE_CTX;
