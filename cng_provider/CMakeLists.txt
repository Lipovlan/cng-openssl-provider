add_library(cng_provider MODULE cng_provider.c
        store/cng_store_functions.c
        keymgmt/cng_keymgmt_functions.c
        signature/cng_signature_functions.c
        ../debug.c)
target_include_directories(cng_provider PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(cng_provider PRIVATE OpenSSL::Crypto ncrypt)

install(TARGETS cng_provider DESTINATION ossl-modules)