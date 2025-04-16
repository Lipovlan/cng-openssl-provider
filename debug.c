#include "debug.h"
#include <stdio.h>

#define DEBUG_LEVEL DEBUG_ALL

void debug_printf(const char *string, int this_level, int global_level) {
    if (this_level <= global_level) {
        BIO *stdoutbio = BIO_new_fd(_fileno(stdout), BIO_NOCLOSE);
        BIO_puts(stdoutbio, string);
        BIO_free(stdoutbio);
    }
}

void start_tracing() {
    /* Tracing: https://www.openssl.org/docs/man3.0/man3/OSSL_trace_set_channel.html */
    static const int openssl_enabled_tracing_categories[] = {
                                                OSSL_TRACE_CATEGORY_CONF,
                                                OSSL_TRACE_CATEGORY_STORE,
                                                // OSSL_TRACE_CATEGORY_TLS,
                                                // OSSL_TRACE_CATEGORY_DECODER
    };

    int categories_count = sizeof(openssl_enabled_tracing_categories) / sizeof(openssl_enabled_tracing_categories[0]);
    for (int i = 0; i < categories_count; i++) {
        /* Each channel has its own BIO for granular control of output */
        BIO *berr = BIO_new_fp(stderr, BIO_NOCLOSE | BIO_FP_TEXT);
        /* https://www.openssl.org/docs/man3.0/man3/OSSL_trace_set_channel.html#Functions
         * Ownership of BIO is changed here, do not free it directly */
        if (!OSSL_trace_set_channel(openssl_enabled_tracing_categories[i], berr)) {
            debug_printf("Error setting OpenSSL tracing\n", DEBUG_ERROR, DEBUG_LEVEL);
            exit(0);
        }

    }

    //OSSL_trace_set_prefix(OSSL_TRACE_CATEGORY_CONF, "BEGIN TRACE[CONF]");
    //OSSL_trace_set_suffix(OSSL_TRACE_CATEGORY_CONF, "END TRACE[CONF]");
    //OSSL_trace_set_prefix(OSSL_TRACE_CATEGORY_STORE, "BEGIN TRACE[STORE]");
    //OSSL_trace_set_suffix(OSSL_TRACE_CATEGORY_STORE, "END TRACE[STORE]");
    //OSSL_trace_set_prefix(OSSL_TRACE_CATEGORY_TLS, "BEGIN TRACE[TLS]");
    //OSSL_trace_set_suffix(OSSL_TRACE_CATEGORY_TLS, "END TRACE[TLS]");
    //OSSL_trace_set_prefix(OSSL_TRACE_CATEGORY_DECODER, "BEGIN TRACE[DECODER]");
    //OSSL_trace_set_suffix(OSSL_TRACE_CATEGORY_DECODER, "END TRACE[DECODER]");
}

