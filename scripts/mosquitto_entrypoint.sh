#!/bin/sh
set -eu
umask 022

(
  i=0
  while [ "$i" -lt 30 ]; do
    if [ -f /logs/mqtt.log ]; then
      chmod 644 /logs/mqtt.log 2>/dev/null || true
      break
    fi
    i=$((i + 1))
    sleep 1
  done
) &

exec /docker-entrypoint.sh "$@"
