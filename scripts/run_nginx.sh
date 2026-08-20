#!/bin/sh

set -e

if [ -z "$1" ]; then
  echo "Usage: [CLIENT_DIR=/path/to/web/client] $0 /path/to/server.pem"
  exit 1
fi

PEM_PATH="$1"
NGINX_IMAGE="${NGINX_IMAGE:-ras-nginx:1.28.0-openssl-1.0.2u}"

if [ ! -f "$PEM_PATH" ]; then
  echo "$PEM_PATH is not a file. Run 'make docker-cert' to generate one."
  exit 1
fi

set -- --rm -it \
  --add-host=host.docker.internal:host-gateway \
  --add-host=open-oscar-server:host-gateway \
  -v "$PEM_PATH:/etc/nginx/certs/server.pem:ro" \
  -v "$(pwd)/config/ssl/nginx.conf:/etc/nginx/nginx.conf:ro" \
  -p 80:80 \
  -p 443:443 \
  -p 5193:5193

# Subdirectories of CLIENT_DIR are served under /client, e.g. the directory
# aim-client is served at /client/aim-client/.
if [ -n "${CLIENT_DIR:-}" ]; then
  mkdir -p "$CLIENT_DIR"
  set -- "$@" -v "$CLIENT_DIR:/srv/client:ro"
fi

docker run "$@" "$NGINX_IMAGE"
