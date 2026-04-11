FROM alpine:3.20
RUN apk add --no-cache bash git build-base autoconf automake libtool openssl-dev

# OpenSSL 3.x potrebuje explicitne povoliť PSK cipher suites cez ssl_conf reťazec.
RUN sed -i 's/^\[openssl_init\]/[openssl_init]\nssl_conf = ssl_sect/' /etc/ssl/openssl.cnf && \
    printf '\n[ssl_sect]\nsystem_default = system_default_sect\n[system_default_sect]\nMinProtocol = DTLSv1\nCipherString = DEFAULT:@SECLEVEL=0\n' >> /etc/ssl/openssl.cnf

# libcoap sa kompiluje zo zdrojov s explicitnou podporou OpenSSL DTLS.
RUN git clone --depth 1 --branch v4.3.5 https://github.com/obgm/libcoap.git /tmp/libcoap && \
    cd /tmp/libcoap && \
    # Oprava 1: v OpenSSL 3.3 je "PSK:!NULL" neplatné, preto sa používa iba "PSK". \
    sed -i 's/#define COAP_OPENSSL_PSK_CIPHERS "PSK:!NULL"/#define COAP_OPENSSL_PSK_CIPHERS "PSK"/' src/coap_openssl.c && \
    # Oprava 2: coap_dtls_context_set_cpsk() neregistruje SSL_CTX_set_psk_client_callback(). \
    # AWK patch sa zapisuje do súboru, aby nevznikli quoting problémy pri RUN reťazci. \
    printf 'BEGIN{in_cpsk=0;patched=0}\n/coap_dtls_context_set_cpsk/{in_cpsk=1}\nin_cpsk&&!patched&&/psk_pki_enabled/{print;print "  SSL_CTX_set_psk_client_callback(o_context->dtls.ctx, coap_dtls_psk_client_callback);";patched=1;next}\n{print}\n' > /tmp/fix_psk.awk && \
    awk -f /tmp/fix_psk.awk src/coap_openssl.c > /tmp/coap_openssl_patched.c && \
    mv /tmp/coap_openssl_patched.c src/coap_openssl.c && \
    grep -c 'SSL_CTX_set_psk_client_callback(o_context->dtls.ctx, coap_dtls_psk_client_callback)' src/coap_openssl.c && \
    # Oprava 3: v secure PSK/PKI režime sa vytvárajú iba secure endpointy, aby port 5683 ostal zatvorený
    # bez potreby firewall capability v kontajneri. \
    printf 'BEGIN{patched=0}\n/for \\(info = info_list; info != NULL; info = info->next\\) \\{/{print; if(!patched){print "    if ((key_defined || cert_file) &&"; print "        (info->proto == COAP_PROTO_UDP || info->proto == COAP_PROTO_TCP)) {"; print "      continue;"; print "    }"; patched=1; next}}{print}\n' > /tmp/fix_secure_endpoints.awk && \
    awk -f /tmp/fix_secure_endpoints.awk examples/coap-server.c > /tmp/coap_server_patched.c && \
    mv /tmp/coap_server_patched.c examples/coap-server.c && \
    grep -c 'info->proto == COAP_PROTO_UDP || info->proto == COAP_PROTO_TCP' examples/coap-server.c && \
    ./autogen.sh && \
    ./configure --disable-tests --disable-documentation --enable-fast-install \
        --with-openssl --enable-dtls && \
    make && make install && \
    cd / && rm -rf /tmp/libcoap /tmp/fix_psk.awk /tmp/fix_secure_endpoints.awk

EXPOSE 5683/udp 5684/udp
CMD ["coap-server", "-A", "0.0.0.0", "-v", "6"]
