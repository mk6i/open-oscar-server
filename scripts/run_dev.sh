#!/bin/sh
# This script launches Open OSCAR Server using go run with the environment vars
# defined in config/settings.env under MacOS/Linux. The script can be run from
# any working directory--it assumes the location of config/command files
# relative to the path of this script.
set -e

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
DEFAULT_ENV_FILE="$SCRIPT_DIR/../config/ssl/settings.env"

if [ "$#" -gt 1 ]; then
  echo "Usage: $0 [path/to/settings.env]"
  exit 1
fi

if [ "$#" -eq 1 ]; then
  ENV_FILE="$1"
else
  ENV_FILE="$DEFAULT_ENV_FILE"
fi
REPO_ROOT="$SCRIPT_DIR/.."

# Run Open OSCAR Server from repo root.
cd "$REPO_ROOT"
go run -v ./cmd/server -config "$ENV_FILE"