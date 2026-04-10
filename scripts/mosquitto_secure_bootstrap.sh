#!/bin/sh
set -eu
umask 022

mqtt_device_password="$(tr -d '\r\n' < /run/secrets/mqtt_device_password)"
mqtt_controller_password="$(tr -d '\r\n' < /run/secrets/mqtt_controller_password)"

mosquitto_passwd -c -b /tmp/passwd device01 "$mqtt_device_password"
mosquitto_passwd -b /tmp/passwd controller01 "$mqtt_controller_password"
chmod 600 /tmp/passwd

exec /usr/sbin/mosquitto -c /mosquitto/config/mosquitto.conf
