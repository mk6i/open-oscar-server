#!/usr/bin/env bash

# docker-setup.sh
# Cross-platform installer for Open OSCAR Server Docker Setup
# Compatible with Linux and macOS

set -e
set -u  # Exit on undefined variables

# ANSI color codes (fallback for POSIX shells that support it)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()    { printf "%b\n" "${CYAN}[*] $1${NC}" >&2; }
success(){ printf "%b\n" "${GREEN}[✔] $1${NC}" >&2; }
warn()   { printf "%b\n" "${YELLOW}[!] $1${NC}" >&2; }
error()  { printf "%b\n" "${RED}[✖] $1${NC}" >&2; return 1; }

prompt() {
    local varname=$1
    local prompt_text=$2

    if [ -t 0 ] && [ -t 1 ]; then
        # Interactive shell with both stdin and stdout connected to terminal
        printf "%b" "$prompt_text"
        read -r "$varname"
    else
        # Non-interactive shell (like curl | bash) or output redirected
        printf "%b" "$prompt_text" >&2
        read -r "$varname" < /dev/tty
    fi

    # Use eval for POSIX-compatible indirect variable access
    local value
    eval "value=\$$varname"
    if [ -z "$value" ]; then
        printf "%b\n" "${RED}[✖] Input required but not provided.${NC}" >&2
        return 1
    fi
}

check_os() {
    case "$(uname -s)" in
        Linux|Darwin)
            : # supported
            ;;
        *)
            error "Unsupported OS: $(uname -s)"
            return 1
            ;;
    esac
}

check_prereqs() {
    log "Checking for required tools..."
    for cmd in git docker make; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            error "Missing required command: $cmd"
            return 1
        fi
    done
    success "All prerequisites are installed."
}

stop_existing_services() {
    log "Stopping any existing Docker Compose services..."
    if docker compose ps -q 2>/dev/null | grep -q .; then
        log "Found running services, stopping them..."
        docker compose down 2>/dev/null || true
        success "Stopped existing services."
    else
        log "No running services found."
    fi
}

resolve_repo_root() {
    SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)

    # If this script is inside a Git repo already, use that
    if git -C "$SCRIPT_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        REPO_ROOT=$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)
    else
        TMP_DIR="open-oscar-server"
        if [ -d "$TMP_DIR/.git" ]; then
            warn "Directory '$TMP_DIR' is already a git repo. Using existing directory."
        else
            log "Cloning Open OSCAR Server repository..."
            if ! git clone https://github.com/mk6i/open-oscar-server.git "$TMP_DIR"; then
                error "Failed to clone repository"
                return 1
            fi
        fi
        REPO_ROOT=$(cd "$TMP_DIR" && pwd)
    fi
    if ! cd "$REPO_ROOT"; then
        error "Failed to enter repository directory"
        return 1
    fi
}

build_images() {
    log "Building Docker images..."
    if ! make docker-images; then
        error "Docker image build failed"
        return 1
    fi
    success "Docker images built successfully."
}

setup_ssl_cert() {
    if ! prompt OSCAR_HOST "Enter the OSCAR_HOST (e.g., ras.dev): "; then
        return 1
    fi
    
    # Validate OSCAR_HOST format (basic hostname validation)
    if ! echo "$OSCAR_HOST" | grep -qE '^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$'; then
        error "Invalid hostname format: $OSCAR_HOST"
        return 1
    fi
    
    # Export OSCAR_HOST so docker-compose can use it
    export OSCAR_HOST

    log "SSL certificate options:"
    printf "%b\n" "${YELLOW}1) Generate self-signed certificate"
    printf "%b"   "2) Use existing PEM certificate at certs/server.pem${NC}\n"

    if ! prompt cert_choice "${CYAN}Choose an option [1/2]: ${NC}"; then
        return 1
    fi

    case "$cert_choice" in
        1)
            log "Generating self-signed SSL certificate for $OSCAR_HOST..."
            make clean-certs
            log "OSCAR_HOST set to ${OSCAR_HOST}"
            if ! make docker-cert OSCAR_HOST="$OSCAR_HOST"; then
                error "Failed to generate self-signed cert"
                return 1
            fi
            success "Self-signed certificate generated."
            ;;
        2)
            if [ ! -f "certs/server.pem" ]; then
                error "certs/server.pem not found. Please place your PEM file there and rerun."
                return 1
            else
                success "Using existing certificate at certs/server.pem."
            fi
            ;;
        *)
            error "Invalid option for certificate setup."
            return 1
            ;;
    esac
}

generate_nss() {
    log "Generating NSS certificate database..."
    if ! make docker-nss; then
        error "Failed to generate NSS cert DB"
        return 1
    fi
    success "NSS certificate database created at certs/nss/"
}

start_server() {
    log "Starting Open OSCAR Server with hostname $OSCAR_HOST..."
    if ! make docker-run-bg OSCAR_HOST="$OSCAR_HOST"; then
        error "Failed to start server"
        return 1
    fi
    success "Open OSCAR Server is running."
}

final_steps() {
    printf "%b\n" "${GREEN}
Open OSCAR Server setup complete!
===================================
Next Steps:

1. Copy the NSS certs from 'certs/nss/' to each AIM 6.2+ client.

2. Ensure clients can resolve '${OSCAR_HOST}' to your server IP.
   Add the following to each client's hosts file if DNS isn't used:

${YELLOW}127.0.0.1 $OSCAR_HOST${NC}

${GREEN}3. For AIM 6.x client setup instructions, see:
   https://github.com/mk6i/open-oscar-server/blob/main/docs/AIM_6_7.md#aim-62-75-setup

Enjoy!
${NC}" >&2
}

main() {
    check_os || return 1
    check_prereqs || return 1
    resolve_repo_root || return 1
    stop_existing_services || return 1
    build_images || return 1
    setup_ssl_cert || return 1
    generate_nss || return 1
    start_server || return 1
    final_steps
}

main "$@"

