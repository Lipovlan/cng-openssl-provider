#include "cng_store_functions.h"
#include <ncrypt.h>
#include "../../debug.h"

#define DEBUG_LEVEL DEBUG_INFO

/**
 * Helper function to initialize the windows certificate store
 * @param store_ctx Our providers store management context
 * @return One on success, zero on error
 */
int initialize_windows_cert_store(T_CNG_STORE_CTX *store_ctx) {

    DWORD store_location_flag = store_ctx->store_location_flag;

    store_ctx->windows_certificate_store = CertOpenStore(
        CERT_STORE_PROV_SYSTEM_A,                      // Provider type
        0,                                             // Encoding type, not used with CERT_STORE_PROV_SYSTEM
        0,                                             // hCryptProv, must be zero
        store_location_flag|CERT_STORE_READONLY_FLAG,  // Location flag, e.g., CERT_SYSTEM_STORE_LOCAL_MACHINE
        store_ctx->windows_system_store_name           // Store name like "MY", "CA", etc.
    );

    if (store_ctx->windows_certificate_store) {
        debug_printf("STORE> The system store is now open.\n", DEBUG_INFO, DEBUG_LEVEL);
        return 1;
    }
    else {
        debug_printf("STORE> The system store did not open.\n", DEBUG_ERROR, DEBUG_LEVEL);
        return 0;
    }

}


/**
* Helper function to load a certificate from the Windows store into our provider context.
*
* This function operates in two distinct modes:
* 1. Targeted Lookup: If a SHA1 fingerprint was provided in the URI (`target_fingerprint`), 
* it performs a direct search for that exact certificate.
* 2. Store Enumeration: If no fingerprint is present, it acts as an iterator, fetching 
* the next available certificate from the store on each call.
*
* No return value. On error, or when there are no more matching certificates to load, 
* the `cert_store_eof` flag is set to 1 (true) to signal End-Of-File to OpenSSL.
*
* @param store_ctx Pointer to our provider's store management context
*/
void load_another_cert_from_store_into_context(T_CNG_STORE_CTX *store_ctx) {

    // --- DIRECT CERTIFICATE TARGETING VIA FINGERPRINT ---
    if (store_ctx->target_fingerprint[0] != '\0') {

        // If we have already yielded this specific certificate to OpenSSL, signal End Of File
        if (store_ctx->prev_cert_ctx != NULL) {
            store_ctx->cert_store_eof = 1;
            CertFreeCertificateContext(store_ctx->prev_cert_ctx);
            store_ctx->prev_cert_ctx = NULL;
            return;
        }

        CRYPT_HASH_BLOB hashBlob;
        BYTE hash[20];

        // Convert the hex string into a byte array
        for (int i = 0; i < 20; i++) {
            unsigned int temp;
            sscanf_s(store_ctx->target_fingerprint + 2 * i, "%02x", &temp);
            hash[i] = (BYTE)temp;
        }

        hashBlob.pbData = hash;
        hashBlob.cbData = 20;

        // Direct lookup for the exact matching certificate
        store_ctx->prev_cert_ctx = CertFindCertificateInStore(
            store_ctx->windows_certificate_store,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0, CERT_FIND_SHA1_HASH, &hashBlob, NULL);

        if (store_ctx->prev_cert_ctx) {
            // Success! Keep EOF at 0 so OpenSSL fetches the context in the next step.
            store_ctx->cert_store_eof = 0;
            debug_printf("STORE> Exact certificate found via fingerprint.\n", DEBUG_TRACE, DEBUG_LEVEL);
        } else {
            // Not found, abort immediately.
            store_ctx->cert_store_eof = 1;
            debug_printf("STORE> Certificate NOT found via fingerprint.\n", DEBUG_ERROR, DEBUG_LEVEL);
        }
        return;
    }

    // --- STANDARD ENUMERATION (Fallback if no fingerprint was provided in the URI) ---
    store_ctx->prev_cert_ctx = CertEnumCertificatesInStore(store_ctx->windows_certificate_store,
        store_ctx->prev_cert_ctx);
    store_ctx->cert_store_eof = !store_ctx->prev_cert_ctx;
}

/**
 * Translate CNG key handle into an OpenSSL key type name
 *
 * @param key The key handle
 * @return NULL on error or unknown key type, on success OpenSSL key type name
 */
const char *get_key_algorithm_name(NCRYPT_KEY_HANDLE key) {
    PBYTE out;
    DWORD out_len;
    SECURITY_STATUS ss;
    const char *name = NULL;

    /* Extract the NCrypt key type name */
    ss = NCryptGetProperty(key, NCRYPT_ALGORITHM_GROUP_PROPERTY, NULL, 0, &out_len, 0);
    if (ss != ERROR_SUCCESS) { return name; }
    DWORD new_out_len;
    out = malloc(out_len);
    if (out == NULL) { return name; }
    ss = NCryptGetProperty(key, NCRYPT_ALGORITHM_GROUP_PROPERTY, out, out_len, &new_out_len, 0);
    if (ss != ERROR_SUCCESS) {
        free(out);
        return name;
    }

    /* Translate the NCrypt key type name into OpenSSL key type name */
    if (!wcscmp((const unsigned short *) out, NCRYPT_RSA_ALGORITHM_GROUP))
        name = "rsaEncryption";
    free(out);
    return name;
}

/* * Attempts to acquire the CNG private key from the current certificate context.
* Returns:
* 1 : Success (Key handle acquired and stored in store_ctx)
* 0 : Fatal error / EOF (Stop searching, return 0 to OpenSSL)
* -1 : Non-fatal error (Key invalid/missing, skip to next certificate)
*/
int cng_store_acquire_private_key(T_CNG_STORE_CTX *store_ctx) {
    DWORD key_spec;
    BOOL caller_must_free;
    NCRYPT_KEY_HANDLE tmp_key_handle;

    BOOL retval = CryptAcquireCertificatePrivateKey(store_ctx->prev_key_cert_ctx,
        CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_SILENT_FLAG, 
        NULL, &tmp_key_handle, &key_spec, &caller_must_free);

    if (retval != TRUE) {
        DWORD err = GetLastError();
        char err_msg[256];
        sprintf_s(err_msg, sizeof(err_msg), "STORE> ERROR: CryptAcquire failed! Error = 0x%08X\n", err);
        debug_printf(err_msg, 1, DEBUG_LEVEL);

        if (store_ctx->target_fingerprint[0] != '\0') {
            store_ctx->priv_key_store_eof = 1;
            return 0; /* Fatal / EOF */
        }
        return -1; /* Continue search */
    } else {
        debug_printf("STORE> SUCCESS: CryptAcquire got the handle!\n", DEBUG_TRACE, DEBUG_LEVEL);
    }

    const char *keytype = get_key_algorithm_name(tmp_key_handle);
    if (!keytype) {
        debug_printf("STORE> ERROR: get_key_algorithm_name returned NULL in Session 0!\n", DEBUG_ERROR, DEBUG_LEVEL);
        NCryptFreeObject(tmp_key_handle);

        if (store_ctx->target_fingerprint[0] != '\0') {
            store_ctx->priv_key_store_eof = 1;
            return 0; /* Fatal / EOF */
        }
        return -1; /* Continue search */
    }

    /* Success: Store the handle */
    store_ctx->key->windows_key_handle = tmp_key_handle;
    return 1;
}

/**
* Helper function to load a private key from the Windows store into our provider context.
*
* This function operates in two distinct modes:
* 1. Targeted Lookup: If a SHA1 fingerprint was provided in the URI, it performs a 
* direct search for that exact certificate and extracts its private key.
* 2. Store Enumeration: If no fingerprint is present, it iterates through the store, 
* extracting private keys from available certificates.
*
* Returns 1 on success, 0 on error or EOF. 
* On error or when there are no more keys, priv_key_store_eof is set to 1.
*
* @param store_ctx Our provider's store management context
*/
int load_another_privkey_from_store_into_context(T_CNG_STORE_CTX *store_ctx) {

    // --- DIRECT CERTIFICATE TARGETING VIA FINGERPRINT ---
    if (store_ctx->target_fingerprint[0] != '\0') {

        // If we already processed the targeted key, signal End Of File and clean up
        if (store_ctx->prev_key_cert_ctx != NULL) {
            store_ctx->priv_key_store_eof = 1;
            CertFreeCertificateContext(store_ctx->prev_key_cert_ctx);
            store_ctx->prev_key_cert_ctx = NULL;
            return 0;
        }

        CRYPT_HASH_BLOB hashBlob;
        BYTE hash[20];

        // Safely convert the hex string into a byte array
        for (int i = 0; i < 20; i++) {
            unsigned int temp;
            sscanf_s(store_ctx->target_fingerprint + 2 * i, "%02x", &temp);
            hash[i] = (BYTE)temp;
        }

        hashBlob.pbData = hash;
        hashBlob.cbData = 20;

        store_ctx->prev_key_cert_ctx = CertFindCertificateInStore(
            store_ctx->windows_certificate_store,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0, CERT_FIND_SHA1_HASH, &hashBlob, NULL);

        if (store_ctx->prev_key_cert_ctx) {
            store_ctx->priv_key_store_eof = 0; 

            // Call the helper function to acquire the key
            int acquire_res = cng_store_acquire_private_key(store_ctx);
            if (acquire_res == 1) return 1;       // Success!

            // If we failed to acquire the key for our specific target, we must abort
            store_ctx->priv_key_store_eof = 1;
            return 0;
        } else {
            // Target not found
            store_ctx->priv_key_store_eof = 1;
            return 0;
        }
    }

    // --- STANDARD ENUMERATION (Fallback) ---
    while (!store_ctx->priv_key_store_eof) {
        store_ctx->prev_key_cert_ctx = CertEnumCertificatesInStore(store_ctx->windows_certificate_store,
            store_ctx->prev_key_cert_ctx);

        store_ctx->priv_key_store_eof = !store_ctx->prev_key_cert_ctx;
        if (store_ctx->priv_key_store_eof) return 0;

        // Call the helper function to acquire the key and handle the routing
        int acquire_res = cng_store_acquire_private_key(store_ctx);
        if (acquire_res == 1) return 1;       // Success!
        if (acquire_res == 0) return 0;       // Fatal error / EOF
        if (acquire_res == -1) continue;      // Key missing or invalid, skip to next cert
    }

    return 0;
}

/**
 * Returns true if arguments for cng_store_open are valid
 *
 * @param provctx provider context
 * @param uri URI from which we load data into our store
 * @return 1 on valid arguments, zero otherwise
 */
int are_store_open_args_ok(void *provctx, const char *uri) {
    if (provctx == NULL || uri == NULL) {
        debug_printf("STORE> Trying to open store with invalid arguments\n", DEBUG_ERROR, DEBUG_LEVEL);
        return 0;
    }
    if (strncmp(uri, "cng://", 6) != 0) {
        debug_printf("STORE> Store opened with invalid URI scheme\n", DEBUG_ERROR, DEBUG_LEVEL);
        return 0;
    }
    return 1;
}

int parse_uri_from_store_open(T_CNG_STORE_CTX *store_ctx, const char *uri) {
    // Ensure the URI is valid and starts with the expected "cng://" scheme
    if (!uri || strncmp(uri, "cng://", 6) != 0) return 0;

    const char* str = uri + 6; 
    const char* at_sign = strchr(str, '@');

    char store_name[64] = { 0 };

    // Extract the store name (the part before the '@' symbol, if present)
    if (at_sign) {
        size_t name_len = at_sign - str;
        if (name_len >= sizeof(store_name)) name_len = sizeof(store_name) - 1;
        strncpy_s(store_name, sizeof(store_name), str, name_len);
    } else {
        // If no '@' is found, treat the entire remaining string as the store name
        strncpy_s(store_name, sizeof(store_name), str, _TRUNCATE);
    }

    // Convert the extracted store name to uppercase to ensure case-insensitive matching
    for (char* p = store_name; *p; ++p) *p = toupper((unsigned char)*p);

    // Map the parsed string to the official Windows system store names
    if (strcmp(store_name, "CA") == 0) store_ctx->windows_system_store_name = "CA";
    else if (strcmp(store_name, "MY") == 0) store_ctx->windows_system_store_name = "MY";
    else if (strcmp(store_name, "ROOT") == 0) store_ctx->windows_system_store_name = "ROOT";
    else return 0; // Invalid or unsupported store name

    // Set the default store location flag
    store_ctx->store_location_flag = CERT_SYSTEM_STORE_CURRENT_USER;

    // Process the location and optional fingerprint if an '@' was found
    if (at_sign) {
        const char* location = at_sign + 1;
        const char* slash = strchr(location, '/');

        // IMPORTANT: Calculate the exact length of the location string to correctly 
        // parse formats like "localmachine/..." without bleeding into the fingerprint
        size_t loc_len = slash ? (size_t)(slash - location) : strlen(location);

        // Determine the target Windows store location based on the URI
        if (_strnicmp(location, "localmachine", loc_len) == 0) {
            store_ctx->store_location_flag = CERT_SYSTEM_STORE_LOCAL_MACHINE;
        } else if (_strnicmp(location, "currentuser", loc_len) == 0) {
            store_ctx->store_location_flag = CERT_SYSTEM_STORE_CURRENT_USER;
        }

        // If a '/' delimiter is present, extract the remaining part as the target SHA1 fingerprint
        if (slash && strlen(slash + 1) > 0) {
            strncpy_s(store_ctx->target_fingerprint, sizeof(store_ctx->target_fingerprint), slash + 1, _TRUNCATE);
        }
    }

    return 1; // URI successfully parsed
}

void init_store_ctx(T_CNG_STORE_CTX *store_ctx) {
    store_ctx->prev_cert_ctx = NULL;
    store_ctx->prev_key_cert_ctx = NULL;
    store_ctx->windows_system_store_name = NULL;
    store_ctx->priv_key_store_eof = 0;
    store_ctx->cert_store_eof = 0;
    memset(store_ctx->target_fingerprint, 0, sizeof(store_ctx->target_fingerprint));
}

/**
 * Create a provider side context with data based on URI
 *
 * @param provctx Provider context
 * @param uri URI from which we load data into our store
 * @return Loader context or NULL on error
 */
void *cng_store_open(void *provctx, const char *uri) {
    debug_printf("cng_store_open\n", DEBUG_TRACE, DEBUG_LEVEL);
    if (!are_store_open_args_ok(provctx, uri)) { return NULL; }
    T_CNG_STORE_CTX *store_ctx = (T_CNG_STORE_CTX *) malloc(sizeof(T_CNG_STORE_CTX));
    if (store_ctx == NULL) {
        debug_printf("Could not allocate memory for store context\n", DEBUG_ERROR, DEBUG_LEVEL);
        return NULL;
    }

    init_store_ctx(store_ctx);

    store_ctx->key = cng_keymgmt_new(provctx);
    if (store_ctx->key == NULL) {
        free(store_ctx);
        return NULL;
    }

    if (!parse_uri_from_store_open(store_ctx, uri)) {
        debug_printf("STORE> Could not parse received URI\n", DEBUG_ERROR, DEBUG_LEVEL);
        cng_keymgmt_free(store_ctx->key);
        free(store_ctx);

        return NULL;
    }

    if (!initialize_windows_cert_store(store_ctx)) {
        cng_keymgmt_free(store_ctx->key);
        free(store_ctx);
        return NULL;
    }


    /* Prepare for loading certificates */
    /* We do not check return value, if there are no keys we'll simply set eof */
    debug_printf("STORE> Trying to preload certificates from store.\n", DEBUG_INFO, DEBUG_LEVEL);
    load_another_cert_from_store_into_context(store_ctx);
    if (store_ctx->cert_store_eof) {
        debug_printf("STORE> No certificates were found in the store when opening it.\n", DEBUG_INFO, DEBUG_LEVEL);
    }
    /* Same story as with certificates */
    debug_printf("STORE> Trying to preload private keys from store.\n", DEBUG_INFO, DEBUG_LEVEL);
    load_another_privkey_from_store_into_context(store_ctx);
    if (store_ctx->priv_key_store_eof) {
        debug_printf("STORE> No private keys were found in the store when opening it.\n", DEBUG_INFO, DEBUG_LEVEL);
    }
    return store_ctx;
}

/**
 *  Return a constant array of descriptor OSSL_PARAM,
 *  for parameters that OSSL_FUNC_store_set_ctx_params() can handle
 *
 * @param provctx Provider context
 * @return Array of descriptors OSSL_FUNC_store_set_ctx_params() can handle
 */
const OSSL_PARAM *cng_store_settable_ctx_params(void *provctx) {
    debug_printf("cng_store_settable_ctx_params\n", DEBUG_TRACE, DEBUG_LEVEL);
    return NULL;
}

/**
 *  Set additional parameters, such as what kind of data to expect,
 *  search criteria, and so on.
 *
 *  Passing params as NULL should return true
 *
 * @param loaderctx
 * @param params
 * @return True on success
 */
int cng_store_set_ctx_params(void *loaderctx, const OSSL_PARAM params[]) {
    debug_printf("cng_store_set_ctx_params\n", DEBUG_TRACE, DEBUG_LEVEL);
    const OSSL_PARAM *p;

    T_CNG_STORE_CTX *store_ctx = loaderctx;

    if (params == NULL) {
        return 1;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_EXPECT))) {
        int param_type = *(int *) p->data;
        //debug_printf("CORE EXPECTS A PARAMETER OF TYPE %d\n", param_type);
        store_ctx->expected_parameter_type = param_type;
    }

    // Other possible values: OSSL_STORE_PARAM_SUBJECT, OSSL_STORE_PARAM_ISSUER, OSSL_STORE_PARAM_SERIAL
    // OSSL_STORE_PARAM_DIGEST, OSSL_STORE_PARAM_FINGERPRINT, OSSL_STORE_PARAM_ALIAS, OSSL_STORE_PARAM_PROPERTIES
    // OSSL_STORE_PARAM_INPUT_TYPE
    return 1;
}

/**
 * Pass the certificate data from our context to an OpenSSL format
 *
 * @param store_ctx Our providers store management context
 * @param object_cb Function to callback with the stores data
 * @param object_cbarg Additional arguments for the callback
 */
void load_another_cert(T_CNG_STORE_CTX *store_ctx, OSSL_CALLBACK *object_cb, void *object_cbarg) {
    static const int object_type_cert = OSSL_OBJECT_CERT;
    OSSL_PARAM cert_params[] = {
            OSSL_PARAM_int(OSSL_OBJECT_PARAM_TYPE, (int *) &object_type_cert),
            OSSL_PARAM_octet_string(OSSL_OBJECT_PARAM_DATA,
                                    store_ctx->prev_cert_ctx->pbCertEncoded,
                                    store_ctx->prev_cert_ctx->cbCertEncoded),
            OSSL_PARAM_END
    };
    object_cb(cert_params, object_cbarg);
    store_ctx->prev_cert_ctx = CertEnumCertificatesInStore(store_ctx->windows_certificate_store,
                                                           store_ctx->prev_cert_ctx);
    if (!store_ctx->prev_cert_ctx) {
        store_ctx->cert_store_eof = 1;
    }
}

/**
 * Pass the private key data from our context to an OpenSSL format
 *
 * If we have an object reference, we must have a data type  - store_result.c:196
 * @param store_ctx Our providers store management context
 * @param object_cb Function to callback with the stores data
 * @param object_cbarg Additional arguments for the callback
 */
int load_another_private_key(T_CNG_STORE_CTX *store_ctx, OSSL_CALLBACK *object_cb, void *object_cbarg) {
    /* Sanity check */
    if (store_ctx->priv_key_store_eof) { return 0; }

    const char *keytype = get_key_algorithm_name(store_ctx->key->windows_key_handle);
    static const int object_type_pkey = OSSL_OBJECT_PKEY;
    OSSL_PARAM privkey_params[] = {
            /* This can be a OSSL_OBJECT_PARAM_REFERENCE instead of OSSL_OBJECT_PARAM_DATA */
            OSSL_PARAM_int(OSSL_OBJECT_PARAM_TYPE, (int *) &object_type_pkey),
            /* When given the string length 0, OSSL_PARAM_utf8_string() figures out the real length */
            OSSL_PARAM_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE, keytype, 0),
            OSSL_PARAM_octet_string(OSSL_OBJECT_PARAM_REFERENCE, store_ctx->key, sizeof(T_CNG_KEYMGMT_KEYDATA)),
            /* Use this to send the private key directly as DER data, no need for signature algorithms later
             * OSSL_PARAM_octet_string(OSSL_OBJECT_PARAM_DATA, cng2_client_private_key_der,
             * cng2_client_private_key_der_len),
             * OSSL_PARAM_utf8_string(OSSL_OBJECT_PARAM_DATA_STRUCTURE, "PrivateKeyInfo", 15) */
            OSSL_PARAM_END
    };
    if (!object_cb(privkey_params, object_cbarg)) {
        return 0;
    }

    /* We do not check return value, in case of error we set eof flag */
    debug_printf("STORE> Preloading private key for future use\n", DEBUG_INFO, DEBUG_LEVEL);
    load_another_privkey_from_store_into_context(store_ctx);

    return 1;
}

/**
 * Load the next object from the URI opened by OSSL_FUNC_store_open(),
 * creates an object abstraction for it,
 * and calls object_cb with it as well as object_cbarg.
 * object_cb will then interpret the object abstraction
 * and do what it can to wrap it or decode it into an OpenSSL structure.
 * In case a passphrase needs to be prompted to unlock an object,
 * pw_cb should be called.
 *
 * @param loaderctx Loader context
 * @param object_cb Object callback
 * @param object_cbarg Object callback arguemnts
 * @param pw_cb Password callback
 * @param pw_cbarg Password callback arguments
 * @return If operation was a success
 */
int cng_store_load(void *loaderctx,
                   OSSL_CALLBACK *object_cb, /* store_result.c ossl_store_handle_load_result */
                   void *object_cbarg, /* store_lib.c load_data OSSL_STORE_INFO * */
                   OSSL_PASSPHRASE_CALLBACK *pw_cb, /* store_lib.c ossl_pw_passphrase_callback_dec */
                   void *pw_cbarg /* store_lib.c &ctx->pwdata */
) {
    debug_printf("cng_store_load\n", DEBUG_TRACE, DEBUG_LEVEL);
    T_CNG_STORE_CTX *store_ctx = loaderctx;

    /* This is only suggested to use to optimize searching */
    /*
    switch (store_ctx->expected_parameter_type) {
        case OSSL_STORE_INFO_NAME:
            break;
        case OSSL_STORE_INFO_PARAMS:
            break;
        case OSSL_STORE_INFO_PUBKEY:
            break;
        case OSSL_STORE_INFO_PKEY:
            load_another_pkey(store_ctx, object_cb, object_cbarg);
            break;
        case OSSL_STORE_INFO_CERT:
            load_another_cert(store_ctx, object_cb, object_cbarg);
            break;
        case OSSL_STORE_INFO_CRL:
            break;
        default:
            debug_printf("IT IS IMPOLITE TO LOAD WITHOUT SETTING EXPECTATIONS\n");
            load_another_cert(store_ctx, object_cb, object_cbarg);
            return 1;
    }
     */
    if (store_ctx->expected_parameter_type != OSSL_STORE_INFO_CERT && !store_ctx->expected_parameter_type) {
        debug_printf("STORE> Core asked for something else than a certificate while loading.", DEBUG_TRACE,
                     DEBUG_LEVEL);
    }
    if (!store_ctx->cert_store_eof) {
        load_another_cert(store_ctx, object_cb, object_cbarg);
        /* when there is a certificate, we cannot fail this query */
        return 1;
    }
    if (!store_ctx->priv_key_store_eof) {
        return load_another_private_key(store_ctx, object_cb, object_cbarg);
    }
    return 0;
}

/**
 * Indicates if the end of the set of objects from the URI has been
 * reached. When that happens, there's no point trying to do any
 * further loading
 *
 * @param loaderctx Loader context
 * @return True if operation was success
 */
int cng_store_eof(void *loaderctx) {
    debug_printf("cng_store_eof\n", DEBUG_TRACE, DEBUG_LEVEL);
    T_CNG_STORE_CTX *store_ctx = loaderctx;
    return (store_ctx->cert_store_eof && store_ctx->priv_key_store_eof); //Or any other eof flag
}

/**
 * Free loader context
 * @param loaderctx Loader context
 * @return True if operation was success
 */
int cng_store_close(void *loaderctx) {
    T_CNG_STORE_CTX *store_ctx = (T_CNG_STORE_CTX *) loaderctx;
    debug_printf("cng_store_close\n", DEBUG_TRACE, DEBUG_LEVEL);
    BOOL cs = CertCloseStore(store_ctx->windows_certificate_store, 0);
    if (cs != TRUE) { return 0; }
    cng_keymgmt_free(store_ctx->key);
    free(store_ctx);
    return 1;
}


const OSSL_DISPATCH cng_store_functions[] = {
        {OSSL_FUNC_STORE_OPEN,                (void (*)(void)) cng_store_open},
        {OSSL_FUNC_STORE_SETTABLE_CTX_PARAMS, (void (*)(void)) cng_store_settable_ctx_params},
        {OSSL_FUNC_STORE_SET_CTX_PARAMS,      (void (*)(void)) cng_store_set_ctx_params},
        {OSSL_FUNC_STORE_LOAD,                (void (*)(void)) cng_store_load},
        {OSSL_FUNC_STORE_EOF,                 (void (*)(void)) cng_store_eof},
        {OSSL_FUNC_STORE_CLOSE,               (void (*)) cng_store_close},
        {0, NULL}
};
