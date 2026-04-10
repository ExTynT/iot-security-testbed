#!/usr/bin/env bash

run_id_from_env() {
  grep '^RUN_ID=' .env | cut -d= -f2
}

require_run_id() {
  local run_id="${RUN_ID:-$(run_id_from_env)}"
  if [ -z "$run_id" ]; then
    echo "Chyba: RUN_ID nie je nastaveny" >&2
    return 1
  fi
  printf '%s\n' "$run_id"
}

run_secret_path() {
  local secret_name="$1"
  local run_id="${2:-$(require_run_id)}"
  printf 'runs/%s/secrets/%s' "$run_id" "$secret_name"
}

read_run_secret() {
  local secret_name="$1"
  local run_id="${2:-$(require_run_id)}"
  local secret_path
  secret_path="$(run_secret_path "$secret_name" "$run_id")"

  if [ ! -f "$secret_path" ]; then
    echo "Chyba: chyba secret subor $secret_path" >&2
    return 1
  fi

  tr -d '\r\n' < "$secret_path"
}
