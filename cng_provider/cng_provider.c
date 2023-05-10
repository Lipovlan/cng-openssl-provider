#include "cng_provider.h"
#include "store/cng_store_functions.h"
#include "keymgmt/cng_keymgmt_functions.h"
#include "signature/cng_signature_functions.h"
#include "../debug.h"
#define DEBUG_LEVEL 1
/**
 * Returns parameters _get_params() can output
 * @param prov Provider context
 * @return OSSL_PARAM array with possible _get_params() values or NULL on error
 */
static const OSSL_PARAM *cng_gettable_params(void *prov) {
    debug_printf("PROV> cng_gettable_params\n", 2, DEBUG_LEVEL);
    return cng_param_types;
}

/**
 * Helper function that return answer to OpenSSL libraries query for provider status
 *
 * As of now, we always report that we are OK
 * @return Provider status
 */
int cng_prov_is_running() {
    debug_printf("PROV> cng_prov_is_running\n", 2, DEBUG_LEVEL);
    return 1;
}

/**
 * Returns information about the provider itself
 *
 * [1] https://www.openssl.org/docs/manmaster/man7/provider-base.html#Provider-parameters
 * @param provctx Providers context
 * @param params Parameters that the caller wants to know as in [1]
 * @return One on success, zero on error
 */
static int cng_get_params(void *provctx, OSSL_PARAM params[]) {
    debug_printf("PROV> cng_get_params\n", 2, DEBUG_LEVEL);

    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, CNG_PROVIDER_NAME_STR))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, CNG_PROVIDER_VERSION_STR))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, CNG_PROVIDER_BUILDINFO_STR))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, cng_prov_is_running()))
        return 0;
    return 1;
}

/**
 * Returns array of function pointers for specific operations indicated by operation_id
 *
 * [1] https://www.openssl.org/docs/manmaster/man7/provider.html#Operations
 * @param provctx Providers context
 * @param operation_id Requested operation as in [1]
 * @param no_cache Whether the OpenSSL core can store the references returned
 * @return OSSL_ALGORITHM array with function pointers of given operation or NULL on error
 */
static const OSSL_ALGORITHM *cng_query_operation(void *provctx,
                                                 int operation_id,
                                                 int *no_cache) {
    debug_printf("PROV> cng_query_operation\n", 2, DEBUG_LEVEL);

    T_CNG_PROVIDER_CTX *tprovctx = provctx;
    *no_cache = 0; /* Do not store references to data we will return */

    switch (operation_id) {
        case OSSL_OP_DIGEST:
            debug_printf("PROV> Digest operations are not supported\n", 3, DEBUG_LEVEL);
            break;
        case OSSL_OP_STORE:
            debug_printf("PROV> Returning cng_store to core\n", 3, DEBUG_LEVEL);
            return cng_store;
        case OSSL_OP_CIPHER:
            debug_printf("PROV> Cipher operations are not supported\n", 3, DEBUG_LEVEL);
            break;
        case OSSL_OP_MAC:
            debug_printf("PROV> Message authentication code operations are not supported\n", 3, DEBUG_LEVEL);
            break;
        case OSSL_OP_KDF:
            debug_printf("PROV> Key derivation functions operations are not supported\n", 3, DEBUG_LEVEL);
            break;
        case OSSL_OP_RAND:
            debug_printf("PROV> Random operations are not supported\n", 3, DEBUG_LEVEL);
            break;
        case OSSL_OP_KEYMGMT:
            debug_printf("PROV> Returning cng_keymgmt to the core\n", 2, DEBUG_LEVEL);
            return cng_keymgmt;
        case OSSL_OP_KEYEXCH:
            debug_printf("PROV> Key exchange operations are not supported\n", 3, DEBUG_LEVEL);
            break;
        case OSSL_OP_SIGNATURE:
            debug_printf("PROV> Returning cng_signature to core\n", 2, DEBUG_LEVEL);
            return cng_signature;
        case OSSL_OP_ASYM_CIPHER:
            debug_printf("PROV> Asymmetric cipher operations are not supported\n", 3, DEBUG_LEVEL);
            break;
        case OSSL_OP_KEM:
            debug_printf("PROV> Key encapsulation operations are not supported\n", 3, DEBUG_LEVEL);
            break;
        case OSSL_OP_ENCODER:
            debug_printf("PROV> Encoder operations are not supported\n", 3, DEBUG_LEVEL);
            break;
        case OSSL_OP_DECODER:
            debug_printf("PROV> Decoding is not supported\n", 3, DEBUG_LEVEL);
            break;
        default:
            debug_printf("PROV> Returning nothing, no algorithm matches\n", 3, DEBUG_LEVEL);
            return NULL;
    }
    return NULL; /* When unsupported return NULL */
}

/* Teardown functions */
static void cng_teardown(void *provctx) {
    debug_printf("PROV> cng_teardown\n", 2, DEBUG_LEVEL);
    free(provctx);
}

/* Functions we provide to the core */
static const OSSL_DISPATCH cng_dispatch_table[] = {
        {OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void)) cng_gettable_params},
        {OSSL_FUNC_PROVIDER_GET_PARAMS,      (void (*)(void)) cng_get_params},
        {OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void)) cng_query_operation},
        {OSSL_FUNC_PROVIDER_TEARDOWN,        (void (*)(void)) cng_teardown},
        {0, NULL}
};

/**
 * Entrypoint for the provider, used for dynamic and static loading
 *
 * Definded in openssl/core.h
 * @param handle OpenSSLs object for this provider, useful only for calling functions given in the in array
 * @param in Functions offered by OpenSSL core to the provider
 * @param out Functions of basic provider functions it provides to the OpenSSL core
 * @param provctx Provider specific context so multiple simultaneous usages are possible
 * @return One on success, zero on error
 */
int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx) {
    debug_printf("PROV> OSSL_provider_init\n", 2, DEBUG_LEVEL);
    *out = cng_dispatch_table;
    *provctx = malloc(sizeof(T_CNG_PROVIDER_CTX));
    if (*provctx == NULL) { return 0; }
    T_CNG_PROVIDER_CTX *tprovctx = *provctx;
    /* Save core functions so we can use them later */
    tprovctx->core_functions = in;
    return 1;
}
