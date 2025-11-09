#!/bin/sh

set -e

if [ -z "$1" ]; then
  echo "Usage: $0 /path/to/server.pem"
  exit 1
fi

PEM_PATH="$1"

docker run --rm -it \
  --add-host=host.docker.internal:host-gateway \
  --add-host=retro-aim-server:host-gateway \
  -v "$PEM_PATH:/etc/stunnel/certs/server.pem:ro" \
  -v "$(pwd)/config/ssl/stunnel.conf:/etc/stunnel/stunnel.conf:ro" \
  -p 443:443 \
  -p 5193:5193 \
  ras-stunnel:5.75-openssl-1.0.2u stunnel.conf