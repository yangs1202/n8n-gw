#!/usr/bin/env bash
set -euo pipefail

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

required=(
  PUBLIC_BASE_URL
  N8N_UPSTREAM_URL
  OIDC_ISSUER_URL
  OIDC_CLIENT_ID
  OIDC_CLIENT_SECRET
  REDIS_URL
  VAULT_ADDR
)

for key in "${required[@]}"; do
  if [[ -z "${!key:-}" ]]; then
    echo "$key is required" >&2
    exit 1
  fi
done

if [[ -z "${VAULT_TOKEN:-}" && ( -z "${VAULT_ROLE_ID:-}" || -z "${VAULT_SECRET_ID:-}" ) ]]; then
  echo "either VAULT_TOKEN or both VAULT_ROLE_ID and VAULT_SECRET_ID are required" >&2
  exit 1
fi

export OIDC_SCOPES="${OIDC_SCOPES:-openid profile email}"
export VAULT_KV_MOUNT="${VAULT_KV_MOUNT:-secret}"
export VAULT_KV_PREFIX="${VAULT_KV_PREFIX:-n8n-gw/users}"
export LOG_LEVEL="${LOG_LEVEL:-info}"

exec go run ./cmd/n8n-proxy
