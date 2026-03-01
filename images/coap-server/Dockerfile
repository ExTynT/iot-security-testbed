FROM alpine:3.20
RUN apk add --no-cache bash git build-base autoconf automake libtool openssl-dev

# Build libcoap from source
RUN git clone --depth 1 --branch v4.3.5 https://github.com/obgm/libcoap.git /tmp/libcoap && \
    cd /tmp/libcoap && \
    ./autogen.sh && \
    ./configure --disable-tests --disable-documentation --enable-fast-install && \
    make && make install && \
    cd / && rm -rf /tmp/libcoap

EXPOSE 5683/udp 5684/udp
ENTRYPOINT ["coap-server"]
CMD ["-v", "9"]
