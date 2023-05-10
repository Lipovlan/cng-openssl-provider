add_library(cng_provider SHARED cng_provider.c
        store/cng_store_functions.c
        keymgmt/cng_keymgmt_functions.c
        signature/cng_signature_functions.c
        ../debug.c)
target_link_libraries(cng_provider ${LINK_LIBS})
add_compile_definitions(_WINDLL)

install(TARGETS cng_provider DESTINATION ossl-modules)