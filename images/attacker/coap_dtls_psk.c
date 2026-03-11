/*
 * coap_dtls_psk.c – Minimal CoAP GET /.well-known/core over DTLS/PSK.
 *
 * Uses OpenSSL directly for reliable DTLS/PSK without libcoap client-side bugs.
 * Demonstrates authentication in the IoT Security Testbed (bachelor thesis).
 *
 * Exit: 0 = DTLS handshake + CoAP response OK
 *        1 = failure (wrong PSK / network error)
 *
 * Usage: coap-dtls-psk <host> <port> <identity> <psk>
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

static const char *g_identity;
static const char *g_psk;

static unsigned int psk_cb(SSL *ssl, const char *hint,
                            char *identity, unsigned int max_id,
                            unsigned char *psk_out, unsigned int max_psk) {
    (void)ssl; (void)hint;
    snprintf(identity, max_id, "%s", g_identity);
    unsigned int n = (unsigned int)strlen(g_psk);
    if (n > max_psk) n = max_psk;
    memcpy(psk_out, g_psk, n);
    return n;
}

/* CoAP 1.0 CON GET /.well-known/core (MID=1) */
static const unsigned char coap_get[] = {
    0x40, 0x01, 0x00, 0x01,                          /* VER=1 T=CON TKL=0 GET MID=1 */
    0xBB, '.','w','e','l','l','-','k','n','o','w','n', /* Uri-Path delta=11 len=11 */
    0x04, 'c','o','r','e'                             /* Uri-Path delta=0  len=4  */
};

int main(int argc, char *argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <host> <port> <identity> <psk>\n", argv[0]);
        return 1;
    }
    g_identity = argv[3];
    g_psk      = argv[4];

    struct addrinfo hints = {0}, *ai;
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(argv[1], argv[2], &hints, &ai) != 0) {
        fprintf(stderr, "[ERROR] Cannot resolve %s\n", argv[1]);
        return 1;
    }

    int fd = socket(ai->ai_family, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); freeaddrinfo(ai); return 1; }

    struct timeval tv = {5, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(fd, ai->ai_addr, ai->ai_addrlen) != 0) {
        perror("connect"); freeaddrinfo(ai); close(fd); return 1;
    }
    freeaddrinfo(ai);

    SSL_CTX *ctx = SSL_CTX_new(DTLS_client_method());
    if (!ctx) { ERR_print_errors_fp(stderr); close(fd); return 1; }

    SSL_CTX_set_psk_client_callback(ctx, psk_cb);
    SSL_CTX_set_cipher_list(ctx, "PSK:@SECLEVEL=0");
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    BIO *bio = BIO_new_dgram(fd, BIO_CLOSE);
    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &tv);

    SSL *ssl = SSL_new(ctx);
    SSL_set_bio(ssl, bio, bio);
    SSL_set_connect_state(ssl);

    printf("[*] Connecting to coaps://%s:%s (identity='%s') ...\n",
           argv[1], argv[2], g_identity);

    if (SSL_do_handshake(ssl) != 1) {
        fprintf(stderr, "[FAIL] DTLS handshake failed – PSK rejected by server\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return 1;
    }
    printf("[OK]   DTLS handshake established – cipher: %s\n", SSL_get_cipher(ssl));

    SSL_write(ssl, coap_get, sizeof(coap_get));

    unsigned char buf[2048];
    int n = SSL_read(ssl, buf, (int)sizeof(buf) - 1);
    if (n > 4) {
        int cls = (buf[1] >> 5) & 0x7;
        int det = buf[1] & 0x1f;
        printf("[OK]   CoAP response %d.%02d (%d bytes)\n", cls, det, n);
        for (int i = 4; i < n - 1; i++) {
            if ((unsigned char)buf[i] == 0xFF) {
                buf[n] = '\0';
                printf("[OK]   Payload: %.*s\n", n - i - 1, buf + i + 1);
                break;
            }
        }
    } else if (n > 0) {
        printf("[OK]   CoAP response received (%d bytes)\n", n);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 0;
}
