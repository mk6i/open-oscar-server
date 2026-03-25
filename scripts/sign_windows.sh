#!/usr/bin/env bash
# Authenticode-sign the Windows PE produced by GoReleaser (osslsigncode + PKCS#11 token).
#
# Usage: sign_windows.sh <artifact.exe>
#
# Remote signing (e.g. GoReleaser in Docker → host USB token):
#   Set SIGN_HTTP_URL to the host signing server, e.g. http://host.docker.internal:8765
#   The server must see the same repo mount (path under .../open-oscar-server/...).
#
# When SKIP_CODE_SIGN=1, exits 0 without signing (unless SIGN_HTTP_URL is set).
#
# For local signing, set:
#   SIGN_PKCS11_ENGINE     - path to libpkcs11 engine (e.g. Homebrew libp11)
#   SIGN_PKCS11_MODULE     - path to vendor PKCS#11 module (.dylib / .so)
#   SIGN_CERT_PEM          - path to signer certificate chain PEM
#   SIGN_KEY_ID            - PKCS#11 key identifier (hex)
#   SIGN_PASSWORD          - token/PIN (optional if not required)
# Optional:
#   SIGN_TIMESTAMP_URL     - default http://time.certum.pl/
#   SIGN_SERVER_TOKEN      - Bearer token if sign_server uses SIGN_SERVER_TOKEN
#
# Example (match your osslsigncode flags; do not commit secrets):
#   export SIGN_PKCS11_ENGINE=/opt/homebrew/.../libpkcs11.dylib
#   export SIGN_PKCS11_MODULE=/usr/local/lib/crypto3PKCS/...dylib
#   export SIGN_CERT_PEM=/path/to/chain.pem
#   export SIGN_KEY_ID=<pkcs11-key-id-hex>
#   export SIGN_PASSWORD='...'
#   make release-sign

set -euo pipefail

artifact="${1:?artifact path required}"

if [[ -n "${SIGN_HTTP_URL:-}" ]]; then
	rel="${artifact#*/open-oscar-server/}"
	if [[ "$rel" == "$artifact" ]]; then
		echo "cannot derive repo-relative path from ${artifact} (expected .../open-oscar-server/...)" >&2
		exit 1
	fi
	url="${SIGN_HTTP_URL%/}/sign"
	payload=$(printf '{"path":"%s"}' "${rel}")
	hdr=()
	if [[ -n "${SIGN_SERVER_TOKEN:-}" ]]; then
		hdr=( -H "Authorization: Bearer ${SIGN_SERVER_TOKEN}" )
	fi
	curl -fsS "${hdr[@]}" -X POST -H "Content-Type: application/json" -d "${payload}" "${url}"
	exit 0
fi

if [[ "${SKIP_CODE_SIGN:-}" == "1" ]]; then
	echo "Skipping Windows Authenticode (SKIP_CODE_SIGN=1)"
	exit 0
fi

: "${SIGN_PKCS11_ENGINE:?set SIGN_PKCS11_ENGINE}"
: "${SIGN_PKCS11_MODULE:?set SIGN_PKCS11_MODULE}"
: "${SIGN_CERT_PEM:?set SIGN_CERT_PEM}"
: "${SIGN_KEY_ID:?set SIGN_KEY_ID}"

timestamp_url="${SIGN_TIMESTAMP_URL:-http://time.certum.pl/}"

tmp="${artifact}.~signing~"
rm -f "${tmp}"

pass_args=()
if [[ -n "${SIGN_PASSWORD:-}" ]]; then
	pass_args+=( -pass "${SIGN_PASSWORD}" )
fi

osslsigncode sign \
	-verbose \
	-pkcs11engine "${SIGN_PKCS11_ENGINE}" \
	-pkcs11module "${SIGN_PKCS11_MODULE}" \
	-certs "${SIGN_CERT_PEM}" \
	-key "${SIGN_KEY_ID}" \
	"${pass_args[@]}" \
	-h sha256 \
	-t "${timestamp_url}" \
	-in "${artifact}" \
	-out "${tmp}"

mv "${tmp}" "${artifact}"
