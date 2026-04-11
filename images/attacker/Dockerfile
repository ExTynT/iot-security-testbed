FROM alpine:3.20

# Nástroje pre MQTT útoky, nešifrovaný CoAP a kompiláciu vlastného DTLS/PSK klienta.
RUN apk add --no-cache bash curl mosquitto-clients libcoap openssl-dev gcc musl-dev

# Vlastný CoAP-over-DTLS/PSK klient používa OpenSSL priamo, aby obišiel chyby PSK klienta v libcoap.
COPY coap_dtls_psk.c /tmp/coap_dtls_psk.c
RUN gcc -O2 -o /usr/local/bin/coap-dtls-psk /tmp/coap_dtls_psk.c -lssl -lcrypto && \
    rm /tmp/coap_dtls_psk.c

RUN addgroup -S attacker -g 10002 && \
    adduser -S -G attacker -u 10002 attacker && \
    mkdir -p /work && \
    chown -R attacker:attacker /work

WORKDIR /work
USER attacker
ENTRYPOINT ["bash"]
