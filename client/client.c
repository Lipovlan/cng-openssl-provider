/*
 *  Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License").  You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://www.openssl.org/source/license.html
 *
 *  This source code has been modified to allow usage on Windows operating system
 *  by Ladislav Marko
 */

/**
 * This program connect via TLS to a server by given ip address and hostname and
 * sends its own client certificate
 */

#include <stdio.h>
#include <string.h>
#include <openssl/provider.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <WinSock2.h>
#include <WS2tcpip.h>

#include "../debug.h"

#define DEBUG_LEVEL 0

#define SERVER_PORT 443
#define SERVER_IP "185.8.165.85"
#define SERVER_COMMON_NAME "cng.ladislavmarko.cz"
#define CNG_URI "cng://MY"
#define SEARCH_FACTOR NID_commonName
#define SEARCH_VALUE "CNG 2 Client"


#include <openssl/trace.h>
#include <openssl/store.h>


SOCKET create_socket() {
    SOCKET s;
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    return s;
}

SSL_CTX *create_context(OSSL_LIB_CTX *libctx) {
    SSL_CTX *ctx;

    ctx = SSL_CTX_new_ex(libctx, "?provider=cng", TLS_client_method());
    // The question mark means that our provider is preferred
    // https://mta.openssl.org/pipermail/openssl-users/2023-February/015831.html
    if (ctx == NULL) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

/*
 * Callback function to log SSL/TLS secrets for later analysis
 */
void ssl_callback(const SSL *ctx, const char *line) {
    FILE *lf;
    fopen_s(&lf, "log.txt", "a");
    fprintf(lf, "%s\n", line);
    fclose(lf);
}

/**
 * Compare common name of certificate with a string
 * @param cert Certificate to have its common name compared
 * @param common_name String to which the common name is compared to
 * @return 1 on match, 0 otherwise
 */
int X509_has_attribute_value(X509 *cert, int nid, const char *common_name) {
    X509_NAME *name = X509_get_subject_name(cert);
    if (name == NULL) { return 0; }

    int loc = X509_NAME_get_index_by_NID(name, nid, -1);
    if (loc == -1) { return 0; } //Multiple common names detected
    ASN1_STRING *str = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(name, loc));

    return (!strcmp(common_name, (char *) str->data));
}

int find_and_use_client_certificate(const char *uri, OSSL_LIB_CTX *libctx, SSL_CTX *ssl_ctx,
                                    EVP_PKEY **private_key_of_certificate) {
    OSSL_STORE_CTX *ossl_store_ctx = OSSL_STORE_open_ex(uri, libctx, NULL, NULL,
                                                        NULL, NULL, NULL, NULL);
    if (ossl_store_ctx == NULL) { return 0; }

    /* Enumerate certificates in the store we just opened */
    while (!OSSL_STORE_eof(ossl_store_ctx)) {
        OSSL_STORE_INFO *info = OSSL_STORE_load(ossl_store_ctx);
        if (info == NULL) {
            OSSL_STORE_close(ossl_store_ctx);
            return 0;
        }

        if (OSSL_STORE_INFO_get_type(info) == OSSL_STORE_INFO_CERT) {
            printf("PROGRAM> Found certificate in store\n");
            X509 *loaded_certificate = OSSL_STORE_INFO_get0_CERT(info);

            /* Print the subject name of the certificate */
            X509_NAME *a = X509_get_subject_name(loaded_certificate);
            BIO *stdoutbio = BIO_new_fd(_fileno(stdout), BIO_NOCLOSE);
            X509_NAME_print(stdoutbio, a, 80);
            BIO_free(stdoutbio);
            printf("\n");

            /* Check that it is the certificate we want */
            if (!X509_has_attribute_value(loaded_certificate, SEARCH_FACTOR, SEARCH_VALUE)) { continue; }
            /* Save the public key, so we can compare it to private one later */
            *private_key_of_certificate = X509_get0_pubkey(loaded_certificate);
            /* Use this certificate for SSL/TLS */
            if (!SSL_CTX_use_certificate(ssl_ctx, loaded_certificate)) {
                printf("PROGRAM> Certificate cannot be loaded into SSL context\n");
                break;
            }
            OSSL_STORE_close(ossl_store_ctx);
            return 1;
        }
    }
    OSSL_STORE_close(ossl_store_ctx);
    return 0;
}

int find_and_use_client_private_key(const char *uri, OSSL_LIB_CTX *libctx, SSL_CTX *ssl_ctx,
                                    EVP_PKEY *certificate_public_key) {
    OSSL_STORE_CTX *ossl_store_ctx = OSSL_STORE_open_ex(uri, libctx, NULL, NULL,
                                                        NULL, NULL, NULL, NULL);
    if (ossl_store_ctx == NULL) { return 0; }

    /* Enumerate keys in the store we just opened */
    while (!OSSL_STORE_eof(ossl_store_ctx)) {
        OSSL_STORE_INFO *info = OSSL_STORE_load(ossl_store_ctx);
        if (info == NULL) {
            OSSL_STORE_close(ossl_store_ctx);
            return 0;
        }

        if (OSSL_STORE_INFO_get_type(info) == OSSL_STORE_INFO_PKEY) {
            printf("PROGRAM> Found private key in store\n");
            EVP_PKEY *pkey = OSSL_STORE_INFO_get0_PKEY(info);
            /* Check that this is the private key of our certificate */
            if (!EVP_PKEY_eq(pkey, certificate_public_key)) { continue; }
            /* Use this private key for SSL/TLS */
            if (!SSL_CTX_use_PrivateKey(ssl_ctx, pkey)) {
                printf("PROGRAM> Private key cannot be loaded into SSL context\n");
                return 0;
            }
            OSSL_STORE_close(ossl_store_ctx);
            return 1;
        }
    }
    OSSL_STORE_close(ossl_store_ctx);
    return 0; // Could not find matching private key
}

void configure_client_context(SSL_CTX *ssl_ctx) {
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_keylog_callback(ssl_ctx, ssl_callback);
}


int main() {
    // Remove old file with SSL/TLS secrets, we do not care much if this fails
    remove("log.txt");

    OSSL_LIB_CTX *libctx;
    start_tracing();

    // LOAD PROVIDERS  ----------------------------------------------------------------------------------
    OSSL_PROVIDER *prov_cng;
    OSSL_PROVIDER *prov_default;

    libctx = OSSL_LIB_CTX_new(); //NULL is default context
    /* Load Multiple providers into the library context */
    prov_cng = OSSL_PROVIDER_load(libctx, "cng_provider");
    if (prov_cng == NULL) {
        printf("PROGRAM> Failed to load CNG provider\n");
        OSSL_PROVIDER_unload(prov_cng);
        exit(EXIT_FAILURE);
    }

    prov_default = OSSL_PROVIDER_load(libctx, "default");
    if (prov_default == NULL) {
        printf("PROGRAM> Failed to load default provider\n");
        OSSL_PROVIDER_unload(prov_cng);
        OSSL_PROVIDER_unload(prov_default);
        exit(EXIT_FAILURE);
    }

    //SSL FROM HERE ----------------------------------------------------------------------------------------
    SSL_CTX *ssl_ctx = NULL;
    SSL *ssl = NULL;

    SOCKET client_skt = INVALID_SOCKET;

    char rxbuf[512];
    size_t rxcap = sizeof(rxbuf);
    int rxlen;

    struct sockaddr_in addr;
    debug_printf("PROGRAM> We will connect to a remote server and check the SSL certificate\n", 0, DEBUG_LEVEL);

    /* Microsoft Docs */
    // The WSAStartup function must be the first Windows Sockets function called by an application or DLL.
    // - https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-wsastartup
    WSADATA wsaData;
    int err;

    err = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (err != 0) {
        printf("PROGRAM> WSAStartup failed with error: %d\n", err);
        exit(1);
    }
    /* End of Microsoft Docs */

    /* Create ssl context used by client */
    ssl_ctx = create_context(libctx);

    /* Configure client context so we verify with the server correctly */
    configure_client_context(ssl_ctx);

    EVP_PKEY *pubkey = NULL;
    if (!find_and_use_client_certificate(CNG_URI, libctx, ssl_ctx, &pubkey)) {
        debug_printf("PROGRAM> Could not find certificate with this common name in store\n", 0, DEBUG_LEVEL);
        goto exit;
    }
    if (!find_and_use_client_private_key(CNG_URI, libctx, ssl_ctx, pubkey)) {
        debug_printf("PROGRAM> Could not find matching private key in store\n", 0, DEBUG_LEVEL);
        goto exit;
    }

    debug_printf("PROGRAM> Setting ssl contex is finished, now creating socket\n", 0, DEBUG_LEVEL);
    /* Create "bare" socket */
    client_skt = create_socket();
    /* Set up connect address */
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, SERVER_IP, &addr.sin_addr.s_addr);
    addr.sin_port = htons(SERVER_PORT);
    /* Do TCP connect with server */
    if (connect(client_skt, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
        perror("PROGRAM> Unable to TCP connect to server");
        goto exit;
    } else {
        printf("PROGRAM> TCP connection to server successful\n");
    }

    /* Create client SSL structure using dedicated client socket */
    ssl = SSL_new(ssl_ctx);
    SSL_set_fd(ssl, client_skt);
    /* Set host name for SNI */
    SSL_set_tlsext_host_name(ssl, SERVER_COMMON_NAME);
    /* Configure server hostname check */
    SSL_set1_host(ssl, SERVER_COMMON_NAME);

    /* Now do SSL connect with server */
    if (SSL_connect(ssl) == 1) {
        debug_printf("PROGRAM> SSL connection to server successful\n\n", 0, DEBUG_LEVEL);

        char *header = "GET / HTTP/1.1\nHost: ";
        char *end = "\n\n";
        size_t msg_len = strlen(header) + strlen(SERVER_COMMON_NAME) + strlen(end) + 1;
        char *msg = malloc(msg_len);
        if (msg == NULL) { exit(2); }
        snprintf(msg, msg_len, "%s%s%s", header, SERVER_COMMON_NAME, end);

        /* Send it to the server */
        if (SSL_write(ssl, msg, msg_len) <= 0) {
            printf("Server closed connection\n");
            ERR_print_errors_fp(stderr);
            free(msg);
            goto exit;
        }

        /* Wait for the response */
        rxlen = SSL_read(ssl, rxbuf, rxcap);
        if (rxlen <= 0) {
            printf("PROGRAM> Server closed connection\n");
            ERR_print_errors_fp(stderr);
            free(msg);
            goto exit;
        } else {
            /* Show it */
            rxbuf[rxlen < rxcap ? rxlen : rxcap - 1] = 0;
            printf("Received: %s\n", rxbuf);
        }
        free(msg);
    } else {
        printf("PROGRAM> SSL connection to server failed\n\n");
        ERR_print_errors_fp(stderr);
    }

    exit:

    /* Close up */
    debug_printf("PROGRAM> Client exiting...\n", 0, DEBUG_LEVEL);
    if (ssl != NULL) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    SSL_CTX_free(ssl_ctx);

    if (client_skt != -1)
        closesocket(client_skt);

    WSACleanup();
    OSSL_PROVIDER_unload(prov_cng);
    OSSL_PROVIDER_unload(prov_default);
    OSSL_LIB_CTX_free(libctx);
    return 0;
}