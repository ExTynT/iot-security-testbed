FROM alpine:3.20

# Tools: mosquitto for MQTT attacks, libcoap for plaintext CoAP, gcc+openssl-dev to compile custom DTLS client
RUN apk add --no-cache bash curl mosquitto-clients libcoap openssl-dev gcc musl-dev

# Custom CoAP-over-DTLS/PSK client (uses OpenSSL directly – bypasses libcoap PSK bugs)
COPY coap_dtls_psk.c /tmp/coap_dtls_psk.c
RUN gcc -O2 -o /usr/local/bin/coap-dtls-psk /tmp/coap_dtls_psk.c -lssl -lcrypto && \
    rm /tmp/coap_dtls_psk.c

WORKDIR /work
ENTRYPOINT ["bash"]
