#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <ncrypt.h>
#include "cng_keymgmt_functions.h"

#define DEBUG_LEVEL DEBUG_ERROR

/**
 * Helper function to duplicate key handles since NCrypt does not provide this functionality
 * @param old_key_handle Old key handle
 * @param new_key_handle New key handle
 * @return One on success, zero on error
 */
int duplicate_key_handle(const NCRYPT_KEY_HANDLE *old_key_handle, NCRYPT_KEY_HANDLE *new_key_handle) {

    /* Get key type flags */
    DWORD key_type_flags;
    DWORD key_type_flags_expected_len = 0;
    SECURITY_STATUS ss2 = NCryptGetProperty(*old_key_handle, NCRYPT_KEY_TYPE_PROPERTY, (PBYTE) &key_type_flags,
                                            sizeof(key_type_flags), &key_type_flags_expected_len, 0);
    if (ss2 != ERROR_SUCCESS || sizeof(key_type_flags) != key_type_flags_expected_len) {
        return 0;
    }

    /* Get key provider */
    NCRYPT_PROV_HANDLE key_provider_handle;
    DWORD key_provider_handle_expected_len = 0;
    ss2 = NCryptGetProperty(*old_key_handle, NCRYPT_PROVIDER_HANDLE_PROPERTY, (PBYTE) &key_provider_handle,
                            sizeof(key_provider_handle), &key_provider_handle_expected_len, 0);
    if (ss2 != ERROR_SUCCESS || sizeof(key_provider_handle) != key_provider_handle_expected_len) {
        return 0;
    }

    /* Get key name */
    LPWSTR key_name = NULL;
    DWORD key_name_len = 0;
    DWORD key_name_expected_len = 0;
    ss2 = NCryptGetProperty(*old_key_handle, NCRYPT_NAME_PROPERTY, (PBYTE) key_name, key_name_len,
                            &key_name_expected_len, 0);
    if (ss2 != ERROR_SUCCESS) {
        return 0;
    }
    key_name = malloc(key_name_expected_len);
    key_name_len = key_name_expected_len;
    ss2 = NCryptGetProperty(*old_key_handle, NCRYPT_NAME_PROPERTY, (PBYTE) key_name, key_name_len,
                            &key_name_expected_len, 0);
    if (ss2 != ERROR_SUCCESS) {
        free(key_name);
        return 0;
    }

    /* open key again */
    ss2 = NCryptOpenKey(key_provider_handle, new_key_handle, key_name, 0, key_type_flags);
    free(key_name);
    return (ss2 == ERROR_SUCCESS);
}

/**
 * Return bits of security as defined in SP800-57.
 * @param rsa_modulus_bits Size of RSA modulus in bits
 * @return Number of security bits or 0 when unknown.
 */
int rsaModulusSizeToStrengthBits(DWORD rsa_modulus_bits) {
    int security_bits = 0;
    if (rsa_modulus_bits > 1024) { security_bits = 80; }
    if (rsa_modulus_bits > 2048) { security_bits = 112; }
    if (rsa_modulus_bits > 3072) { security_bits = 128; }
    if (rsa_modulus_bits > 7680) { security_bits = 192; }
    if (rsa_modulus_bits > 15360) { security_bits = 256; }
    return security_bits;
}

/**
 * Allocates a new buffer and copies the original one into it in reverse byte by byte.
 *
 * @param buffer Input buffer to be copied in reverse
 * @param buffer_size Size of the buffer to be copied, will also be the size of the newly allocated reverse buffer
 * @return Pointer to newly allocated reverse buffer or NULL on error
 */
unsigned char *duplicate_buffer_in_reverse(const unsigned char *buffer, const ULONG buffer_size) {
    unsigned char *reverse_buffer = malloc(buffer_size);
    if (reverse_buffer == NULL) { return NULL; }
    for (int i = 0; i < buffer_size; i++) {
        reverse_buffer[i] = *(buffer + buffer_size - i - 1);
    }
    return reverse_buffer;
}

/**
 * Allocates a new char buffer in which will the name of the given key be stored.
 *
 * @param key Key whose name is sought
 * @return Pointer to a string buffer with keys name or NULL on error
 */
wchar_t *get_key_name(T_CNG_KEYMGMT_KEYDATA *key) {
    DWORD size;
    SECURITY_STATUS ss = NCryptGetProperty(key->windows_key_handle, NCRYPT_NAME_PROPERTY, NULL, 0, &size, 0);
    if (ss == ERROR_SUCCESS) {
        unsigned char *name = malloc(size);
        if (name == NULL) { return NULL; }
        NCryptGetProperty(key->windows_key_handle, NCRYPT_NAME_PROPERTY, name, size, &size, 0);
        return (wchar_t *) name;
    }
    return NULL;
}

/**
 * Create new provider side key object to be used with other KEYMGMT and SIGNATURE functions
 *
 * @param provctx Provider context, unused
 * @return New provider side key object or NULL on failure
 */
void *cng_keymgmt_new(void *provctx) {
    debug_printf("KEYMGMT> cng_keymgmt_new\n", DEBUG_TRACE, DEBUG_LEVEL);
    T_CNG_KEYMGMT_KEYDATA *keydata = malloc(sizeof(T_CNG_KEYMGMT_KEYDATA));
    if (keydata == NULL) { return NULL; }
    keydata->windows_key_handle = 0;
    return keydata;
}

/**
 * Duplicate the provider side key object
 *
 * [1] https://www.openssl.org/docs/manmaster/man7/provider-keymgmt.html
 * @param keydata_from Old provider side key object
 * @param selection Selection bit as in [1]
 * @return New provider side key object or NULL on failure
 */
void *cng_keymgmt_dup(const void *keydata_from, int selection) {
    debug_printf("KEYMGMT> cng_keymgmt_dup\n", DEBUG_TRACE, DEBUG_LEVEL);
    const T_CNG_KEYMGMT_KEYDATA *old_keydata = keydata_from;
    T_CNG_KEYMGMT_KEYDATA *new_keydata = cng_keymgmt_new(NULL); /* We do not use provider context in keys */
    if (!duplicate_key_handle(&old_keydata->windows_key_handle, &new_keydata->windows_key_handle)) {
        return NULL;
    }
    return new_keydata;
}

/**
 * Free provider side key object
 * @param vkeydata Provider side key object to be deleted
 */
void cng_keymgmt_free(void *vkeydata) {
    debug_printf("KEYMGMT> cng_keymgmt_free\n", DEBUG_TRACE, DEBUG_LEVEL);
    T_CNG_KEYMGMT_KEYDATA *keydata = vkeydata;
    NCryptFreeObject(keydata->windows_key_handle);
    free(keydata);
}

/**
 * Construct a provider side key object based on an object (reference) received from a function compatible with this
 * provider. Usually received from OSSL_PARAM array passed from a store_load() function in STOREMGMT module of provider.
 *
 * @param reference An abstraction that only this provider knows how to interpret. For us, T_CNG_KEYMGMT_KEYDATA
 * @param reference_sz Size of the given reference
 * @return Provider side key object
 */
void *cng_keymgmt_load(const void *reference, size_t reference_sz) {
    debug_printf("KEYMGMT> cng_keymgmt_load\n", DEBUG_TRACE, DEBUG_LEVEL);
    const T_CNG_KEYMGMT_KEYDATA *key = reference;

    //Here we load (from store) our secret key based on the reference of size reference_sz. This is purely provider side thing
    return cng_keymgmt_dup(key, OSSL_KEYMGMT_SELECT_ALL);
}

/**
 * Returns parameter data about given key
 *
 * like the number of security bits. These are listed
 * in https://www.openssl.org/docs/manmaster/man7/provider-keymgmt.html#Common-Information-Parameters
 * @param keydata Provider side key object
 * @param params Requested parameters
 * @return One on success, zero on error
 */
int cng_keymgmt_get_params(void *keydata, OSSL_PARAM params[]) {
    T_CNG_KEYMGMT_KEYDATA *key = keydata;
    debug_printf("KEYMGMT> cng_keymgmt_get_params\n", DEBUG_TRACE, DEBUG_LEVEL);
//    wchar_t *key_name = get_key_name(key);
//    if (key_name != NULL) {
//        printf("KEYMGMT> Core wants params of %ls\n", key_name);
//        free(key_name);
//    }
    OSSL_PARAM *p;
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    /* The value should be the cryptographic length of the cryptosystem to which the key belongs, in bits.
     * The definition of cryptographic length is specific to the key cryptosystem. */
    if (p != NULL && !OSSL_PARAM_set_int(p, 512))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
    /* The value should be the number of security bits of the given key. Bits of security is defined in SP800-57. */
    /* The value should be the maximum size that a caller should allocate to safely store a signature */
    if (p != NULL) {
        DWORD key_length;
        DWORD received_bytes;
        SECURITY_STATUS ss = NCryptGetProperty(key->windows_key_handle, NCRYPT_LENGTH_PROPERTY, (PBYTE) &key_length,
                                               sizeof(key_length), &received_bytes, 0);
        if (ss != ERROR_SUCCESS || received_bytes != sizeof(key_length)) { return 0; }

        if (!OSSL_PARAM_set_int(p, rsaModulusSizeToStrengthBits(key_length))) { return 0; }
    }

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
    if (p != NULL && !OSSL_PARAM_set_int(p, 4096))
        return 0;
    return 1;
}

/**
 *  Return parameters we can provide through keymgmt_get_params()
 * @param provctx Provider context
 * @return constant OSSL_PARAM arrray with known parameters
 */
const OSSL_PARAM *cng_keymgmt_gettable_params(void *provctx) {
    debug_printf("KEYMGMT> cng_keymgmt_gettable_params\n", 2, DEBUG_LEVEL);
    return cng_keymgmt_param_types;
}

/**
 * Check if provider side key object has particular key part associated
 * @param keydata Provider side key object
 * @param selection Standard selection of key parts
 * @return Whether or not the key object has that selection
 */
int cng_keymgmt_has(const void *keydata, int selection) {
    debug_printf("KEYMGMT> cng_keymgmt_has key structure", DEBUG_TRACE, DEBUG_LEVEL);
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) { debug_printf(" private key", DEBUG_ALL, DEBUG_LEVEL); }
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) { debug_printf(" public key", DEBUG_ALL, DEBUG_LEVEL); }
    if (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) { debug_printf(" domain parameters", DEBUG_ALL, DEBUG_LEVEL); }
    if (selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) { debug_printf(" other parameters", DEBUG_ALL, DEBUG_LEVEL); }
    debug_printf("?\n", DEBUG_ALL, DEBUG_LEVEL);
    /* Our keys always have valid public and private parts, additional information is not meaningful, so we
     * can always return true */
    return 1;
}


/**
 * Export data from key given the selection bits
 *
 * The callback is usually evp_keymgmt_util_try_import - keymgmt_lib.c:164
 * [1] https://www.openssl.org/docs/manmaster/man7/provider-keymgmt.html
 * @param keydata Provider side key object
 * @param selection Selection bits as in [1]
 * @param param_cb Callback function that needs to be called with the data being exported for successful return value
 * @param cbarg Arguments for the callback function
 * @return One on success, zero on error
 */
int cng_keymgmt_export(void *keydata, int selection,
                       OSSL_CALLBACK *param_cb, void *cbarg) {
    debug_printf("KEYMGMT> cng_keymgmt_export\n", DEBUG_TRACE, DEBUG_LEVEL);

    T_CNG_KEYMGMT_KEYDATA *cng_keydata = (T_CNG_KEYMGMT_KEYDATA *) keydata;
    OSSL_PARAM *p = NULL;
    OSSL_PARAM params[3];

    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        debug_printf("KEYMGMT> Somebody wants private key exported\n", DEBUG_ALL, DEBUG_LEVEL);
        /* Tough luck, no private key exporting planned */
        return 0;
    }

    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        debug_printf("KEYMGMT> Somebody wants public key exported\n", DEBUG_ALL, DEBUG_LEVEL);
        DWORD public_blob_size;
        SECURITY_STATUS ss = NCryptExportKey(cng_keydata->windows_key_handle, 0, BCRYPT_RSAPUBLIC_BLOB, NULL, NULL, 0,
                                             &public_blob_size, 0);
        if (ss != ERROR_SUCCESS) { return 0; }
        DWORD publicBlobExpectedSize = public_blob_size;
        PBYTE public_blob = malloc(public_blob_size);
        if (public_blob == NULL) { return 0; }
        ss = NCryptExportKey(cng_keydata->windows_key_handle, 0, BCRYPT_RSAPUBLIC_BLOB, NULL, public_blob,
                             publicBlobExpectedSize, &public_blob_size, 0);
        if (ss != ERROR_SUCCESS) {
            free(public_blob);
            return 0;
        }
        BCRYPT_RSAKEY_BLOB *pb = (BCRYPT_RSAKEY_BLOB *) public_blob;

        /* The endianness of CNG is opposite to what OpenSSL uses, reverse it first */
        unsigned char *rsa_public_exp_little_endian = duplicate_buffer_in_reverse(
                public_blob + sizeof(BCRYPT_RSAKEY_BLOB), pb->cbPublicExp);
        if (rsa_public_exp_little_endian == NULL) {
            free(public_blob);
            return 0;
        }
        unsigned char *rsa_modulus_little_endian = duplicate_buffer_in_reverse(
                public_blob + sizeof(BCRYPT_RSAKEY_BLOB) + pb->cbPublicExp, pb->cbModulus);
        if (rsa_modulus_little_endian == NULL) {
            free(public_blob);
            free(rsa_public_exp_little_endian);
            return 0;
        }
        params[0] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_E, rsa_public_exp_little_endian,
                                            pb->cbPublicExp);
        params[1] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_N, rsa_modulus_little_endian,
                                            pb->cbModulus);
        params[2] = OSSL_PARAM_construct_end();
        p = params;
    }

    if (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) {
        debug_printf("KEYMGMT>  Somebody wants domain parameters exported\n", DEBUG_ALL, DEBUG_LEVEL);
        if (p == NULL) { return 0; }
    }

    if (selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) {
        debug_printf("KEYMGMT> Somebody wants other parameters exported\n", DEBUG_ALL, DEBUG_LEVEL);
        if (p == NULL) { return 0; }
    }

    return param_cb(p, cbarg);
}

/**
 * Returns what data can _keymgmt_export() export
 *
 * [1] https://www.openssl.org/docs/manmaster/man7/provider-keymgmt.html
 * @param selection Selection bits as in [1]
 * @return The OSSL_PARAM array with values the _keymgmt_export() can return
 */
const OSSL_PARAM *cng_keymgmt_export_types(int selection) {
    debug_printf("KEYMGMT> cng_keymgmt_export_types\n", DEBUG_TRACE, DEBUG_LEVEL);
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        static const OSSL_PARAM export_param_table[] = {
                OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
                OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0),
                OSSL_PARAM_END
        };
        return export_param_table;
    } else {
        return NULL;
    }
}

/**
 * Returns what data can _keymgmt_export() export
 *
 * [1] https://www.openssl.org/docs/manmaster/man7/provider-keymgmt.html
 * @param provctx Provider context
 * @param selection Selection bits as in [1]
 * @return The OSSL_PARAM array with values the _keymgmt_export() can return
 */
const OSSL_PARAM *cng_keymgmt_export_types_ex(void *provctx, int selection) {
    debug_printf("KEYMGMT> cng_keymgmt_export_types_ex\n", DEBUG_TRACE, DEBUG_LEVEL);
    return cng_keymgmt_export_types(selection);
}


/* OSSL_DISPATCH array of provider functions callable from OpenSSL libraries */
const OSSL_DISPATCH cng_keymgmt_functions[] = {
        {OSSL_FUNC_KEYMGMT_NEW,             (void (*)(void)) cng_keymgmt_new},
        {OSSL_FUNC_KEYMGMT_DUP,             (void (*)(void)) cng_keymgmt_dup},
        {OSSL_FUNC_KEYMGMT_FREE,            (void (*)(void)) cng_keymgmt_free},
        {OSSL_FUNC_KEYMGMT_LOAD,            (void (*)(void)) cng_keymgmt_load},
        {OSSL_FUNC_KEYMGMT_GET_PARAMS,      (void (*)(void)) cng_keymgmt_get_params},
        {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void)) cng_keymgmt_gettable_params},
        {OSSL_FUNC_KEYMGMT_HAS,             (void (*)(void)) cng_keymgmt_has},
        {OSSL_FUNC_KEYMGMT_EXPORT,          (void (*)(void)) cng_keymgmt_export},
        {OSSL_FUNC_KEYMGMT_EXPORT_TYPES,    (void (*)(void)) cng_keymgmt_export_types},
        {OSSL_FUNC_KEYMGMT_EXPORT_TYPES_EX,    (void (*)(void)) cng_keymgmt_export_types_ex},
        {0, NULL}
};
