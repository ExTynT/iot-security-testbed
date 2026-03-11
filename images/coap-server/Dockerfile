FROM alpine:3.20
RUN apk add --no-cache bash git build-base autoconf automake libtool openssl-dev

# OpenSSL 3.x: properly enable PSK cipher suites via ssl_conf chain
RUN sed -i 's/^\[openssl_init\]/[openssl_init]\nssl_conf = ssl_sect/' /etc/ssl/openssl.cnf && \
    printf '\n[ssl_sect]\nsystem_default = system_default_sect\n[system_default_sect]\nMinProtocol = DTLSv1\nCipherString = DEFAULT:@SECLEVEL=0\n' >> /etc/ssl/openssl.cnf

# Build libcoap from source with explicit OpenSSL DTLS support
RUN git clone --depth 1 --branch v4.3.5 https://github.com/obgm/libcoap.git /tmp/libcoap && \
    cd /tmp/libcoap && \
    # Fix 1: "PSK:!NULL" is invalid in OpenSSL 3.3; use "PSK" instead \
    sed -i 's/#define COAP_OPENSSL_PSK_CIPHERS "PSK:!NULL"/#define COAP_OPENSSL_PSK_CIPHERS "PSK"/' src/coap_openssl.c && \
    # Fix 2: coap_dtls_context_set_cpsk() never registers SSL_CTX_set_psk_client_callback(). \
    # Write the awk patch script to a file to avoid quoting issues, then apply it. \
    printf 'BEGIN{in_cpsk=0;patched=0}\n/coap_dtls_context_set_cpsk/{in_cpsk=1}\nin_cpsk&&!patched&&/psk_pki_enabled/{print;print "  SSL_CTX_set_psk_client_callback(o_context->dtls.ctx, coap_dtls_psk_client_callback);";patched=1;next}\n{print}\n' > /tmp/fix_psk.awk && \
    awk -f /tmp/fix_psk.awk src/coap_openssl.c > /tmp/coap_openssl_patched.c && \
    mv /tmp/coap_openssl_patched.c src/coap_openssl.c && \
    grep -c 'SSL_CTX_set_psk_client_callback(o_context->dtls.ctx, coap_dtls_psk_client_callback)' src/coap_openssl.c && \
    ./autogen.sh && \
    ./configure --disable-tests --disable-documentation --enable-fast-install \
        --with-openssl --enable-dtls && \
    make && make install && \
    cd / && rm -rf /tmp/libcoap /tmp/fix_psk.awk

# iptables needed for secure scenario: block plaintext port 5683
RUN apk add --no-cache iptables

EXPOSE 5683/udp 5684/udp
CMD ["coap-server", "-A", "0.0.0.0", "-v", "6"]
