#pragma once

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <string.h>

#define CNG_PROVIDER_NAME_STR "OpenSSL Cryptographic API: New Generation Provider"
#define CNG_PROVIDER_VERSION_STR "0.2"
#define CNG_PROVIDER_BUILDINFO_STR "Made for OpenSSL 3.2"

static const char CNG_DEFAULT_ALG_PROPERTIES[] = "provider=cng_provider,fips=no";

/* This function is used by OpenSSL to get  information about the provider
 * for example its version or name */
static OSSL_FUNC_provider_get_params_fn cng_get_params;
/* Although gettable_params() was not called during testing, the documentation mandates, that
 * the existence of get_params() implies the existence of gettable_params() */
static OSSL_FUNC_provider_gettable_params_fn cng_gettable_params;
/* Return function pointers to OpenSSL libraries to functions of this provider's modules */
static OSSL_FUNC_provider_query_operation_fn cng_query_operation;
/* Shut down the provider and destroy its context */
static OSSL_FUNC_provider_teardown_fn cng_teardown;

/* Other core provider functions */
/* Informs the provider, that the result of query_operation() is no longer needed */
//static OSSL_FUNC_provider_unquery_operation_fn cng_unquery_operation;
/* Provides reason strings for core_put_error() */
//static OSSL_FUNC_provider_get_reason_strings cng_get_reason_strings;
/* Provides capabilities up front without having to enumerate all functions of provider
 * For example if the provider supports TLS1.3 ciphersuites */
//static OSSL_FUNC_provider_get_capabilities cng_get_capabilities;
/* This function is used when your provider needs to perform known answer tests on itself */
//static OSSL_FUNC_provider_self_test cng_self_test;

/** Parameters we provide to the core **/
static const OSSL_PARAM cng_param_types[] = {
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
        OSSL_PARAM_END
};

/* Our custom providers context*/
typedef struct s_cng_provider_ctx {
    const OSSL_DISPATCH *core_functions;
} T_CNG_PROVIDER_CTX;

int cng_prov_is_running();

//TODO: maybe use OPENSSL_zalloc(sizeof(*ret)?