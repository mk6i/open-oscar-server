################################################################################
# Build & release helpers
################################################################################

DOCKER_IMAGE_TAG_GO_RELEASER := goreleaser/goreleaser:v2.15.4
# Docker builds cannot load a macOS USB PKCS#11 token. Options: (1) SKIP_CODE_SIGN=1 and skip;
# (2) SIGN_HTTP_URL=http://host.docker.internal:8765 plus `make sign-server` on the host to
# sign via HTTP; (3) run release-sign with host goreleaser (no Docker).
SKIP_CODE_SIGN ?= 1
# When set (e.g. http://host.docker.internal:8765), GoReleaser in Docker calls the host
# sign_server to run PKCS#11 signing on the same bind-mounted dist/ tree.
SIGN_HTTP_URL ?=
SIGN_SERVER_TOKEN ?=
GORELEASER ?= goreleaser
GOLANGCI_LINT ?= golangci-lint

DOCKER_RUN_GO_RELEASER := @docker run \
	--env CGO_ENABLED=0 \
	--env GITHUB_TOKEN=$(GITHUB_TOKEN) \
	--env SKIP_CODE_SIGN=$(SKIP_CODE_SIGN) \
	--env SIGN_HTTP_URL=$(SIGN_HTTP_URL) \
	--env SIGN_SERVER_TOKEN=$(SIGN_SERVER_TOKEN) \
	--rm \
	--volume `pwd`:/go/src/open-oscar-server \
	--workdir /go/src/open-oscar-server \
	$(DOCKER_IMAGE_TAG_GO_RELEASER)
OSCAR_HOST ?= ras.dev
# Tag of the SSL terminator image. docker-compose.yaml defaults to the same
# value, so keep the two in sync when bumping nginx.
NGINX_IMAGE ?= ras-nginx:1.28.0-openssl-1.0.2u
# Host directory holding the web client that nginx serves.
CLIENT_DIR ?= ./clients

.PHONY: config-basic config-ssl config
config-basic: ## Generate basic config file template
	go run ./cmd/config_generator unix config/settings.env basic

config-ssl: ## Generate SSL config file template
	go run ./cmd/config_generator unix config/ssl/settings.env ssl

config: config-basic config-ssl ## Generate all config file templates from Config struct

.PHONY: lint
lint: ## Run formatting and static analysis checks
	@fmt_output="$$(gofmt -s -l .)"; \
	if [ -n "$$fmt_output" ]; then \
		echo "The following files need formatting:"; \
		echo "$$fmt_output"; \
		exit 1; \
	fi
	$(GOLANGCI_LINT) run ./...
	go vet ./...

.PHONY: release
release: ## Run a clean, full GoReleaser run (publish + validate)
	$(DOCKER_RUN_GO_RELEASER) --clean

.PHONY: release-dry-run
release-dry-run: ## GoReleaser dry-run (skips validate & publish)
	$(DOCKER_RUN_GO_RELEASER) --clean --skip=validate --skip=publish

SIGN_SERVER_PORT ?= 8765

.PHONY: sign-server
sign-server: ## Local HTTP signer for Windows PE (run before Docker release if using SIGN_HTTP_URL)
	go run ./cmd/sign_server

.PHONY: sign-server-stop
sign-server-stop: ## Stop whatever is listening on SIGN_SERVER_PORT (usually a leftover sign_server)
	-@kill $$(lsof -t -iTCP:$(SIGN_SERVER_PORT) -sTCP:LISTEN) 2>/dev/null || true

# Default URL for GoReleaser-in-Docker → host signing (Docker Desktop Mac/Win).
# On Linux Docker, use host.docker.internal:8765 only if you add
# --add-host=host.docker.internal:host-gateway to the docker run (or set SIGN_DOCKER_URL).
SIGN_DOCKER_URL ?= http://host.docker.internal:8765

.PHONY: release-dry-run-sign-docker
release-dry-run-sign-docker: ## Dry-run in Docker; Windows Authenticode via host sign_server (run `make sign-server` first)
	@$(MAKE) release-dry-run SIGN_HTTP_URL=$(SIGN_DOCKER_URL)

.PHONY: release-sign-docker
release-sign-docker: ## Full release in Docker; Windows Authenticode via host sign_server (run `make sign-server` first)
	@$(MAKE) release SIGN_HTTP_URL=$(SIGN_DOCKER_URL)

.PHONY: release-dry-run-nosign
release-dry-run-nosign: ## GoReleaser dry-run on host without Windows Authenticode
	SKIP_CODE_SIGN=1 $(GORELEASER) --clean --skip=validate --skip=publish

.PHONY: release-nosign
release-nosign: ## Full GoReleaser on host without Windows Authenticode
	SKIP_CODE_SIGN=1 $(GORELEASER) --clean

.PHONY: release-dry-run-sign
release-dry-run-sign: ## GoReleaser dry-run on host with Windows signing (needs $(GORELEASER), PKCS#11 env)
	SKIP_CODE_SIGN=0 $(GORELEASER) --clean --skip=validate --skip=publish

.PHONY: release-sign
release-sign: ## Full GoReleaser on host with Windows signing (needs $(GORELEASER), PKCS#11 env)
	SKIP_CODE_SIGN=0 $(GORELEASER) --clean

.PHONY: docker-image-ras
docker-image-ras: ## Build Open OSCAR Server image
	docker build -t ras:latest -f Dockerfile .

.PHONY: docker-image-nginx
docker-image-nginx: ## Build nginx image pinned to v1.28.0 / OpenSSL 1.0.2u
	docker build -t $(NGINX_IMAGE) -f Dockerfile.nginx .

.PHONY: docker-image-certgen
docker-image-certgen: ## Build minimal helper image with openssl & nss tools
	docker build -t ras-certgen:latest -f Dockerfile.certgen .

.PHONY: docker-images
docker-images: docker-image-ras docker-image-nginx docker-image-certgen

.PHONY: docker-run
docker-run:
	OSCAR_HOST=$(OSCAR_HOST) NGINX_IMAGE=$(NGINX_IMAGE) CLIENT_DIR=$(CLIENT_DIR) docker compose up open-oscar-server nginx

.PHONY: docker-run-bg
docker-run-bg: ## Run Open OSCAR Server in background with docker-compose
	OSCAR_HOST=$(OSCAR_HOST) NGINX_IMAGE=$(NGINX_IMAGE) CLIENT_DIR=$(CLIENT_DIR) docker compose up -d open-oscar-server nginx

.PHONY: docker-run-stop
docker-run-stop: ## Stop Open OSCAR Server docker-compose services
	OSCAR_HOST=$(OSCAR_HOST) NGINX_IMAGE=$(NGINX_IMAGE) CLIENT_DIR=$(CLIENT_DIR) docker compose down

.PHONY: run
run: # run the server with plain socket config
	./scripts/run_dev.sh ./config/settings.env

.PHONY: run-ssl
run-ssl: # run the server with ssl socket config
	./scripts/run_dev.sh ./config/ssl/settings.env

.PHONY: run-nginx
run-nginx: # run nginx for SSL termination
	NGINX_IMAGE=$(NGINX_IMAGE) CLIENT_DIR=$(CLIENT_DIR) ./scripts/run_nginx.sh ./certs/server.pem

################################################################################
# SSL Helpers
################################################################################

.PHONY: docker-cert
docker-cert: clean-certs ## Create SSL certificates for server
	mkdir -p certs/
	OSCAR_HOST=$(OSCAR_HOST) docker compose run --no-TTY --rm cert-gen

.PHONY: docker-nss
docker-nss: ## Create NSS certificate database for AIM 6.x clients
	OSCAR_HOST=$(OSCAR_HOST) docker compose run --no-TTY --rm nss-gen

.PHONY: clean-certs
clean-certs: ## Remove all generated certificates & NSS DB
	rm -rf certs/*

# Root CA that docker-cert mints, and the common name it is filed under in the
# keychain.
CA_CERT ?= ./certs/ca.crt
CA_CERT_CN ?= Open OSCAR Server Root CA

.PHONY: macos-trust-ca
macos-trust-ca: ## Trust $(CA_CERT) as a root in the macOS system keychain, replacing any previous copy
	@[ "$$(uname)" = "Darwin" ] || { echo "macos-trust-ca only runs on macOS"; exit 1; }
	@[ -f $(CA_CERT) ] || { echo "$(CA_CERT) not found, run 'make docker-cert' first"; exit 1; }
# Authenticate before the loop below, whose 2>/dev/null would otherwise hide a
# sudo password failure and report it as "no previous certificate".
	@sudo -v
# Every prior copy goes, not just the first: delete-certificate removes one match
# per call, and a stale root left behind still validates old certs.
	@while sudo security delete-certificate -c "$(CA_CERT_CN)" /Library/Keychains/System.keychain 2>/dev/null; do \
		echo "removed previous $(CA_CERT_CN)"; \
	done
	sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain $(CA_CERT)

################################################################################
# Web API Tools
################################################################################

.PHONY: webapi-keygen
webapi-keygen: ## Build the Web API key generator tool
	go build -o webapi_keygen ./cmd/webapi_keygen

.PHONY: webapi-keygen-install
webapi-keygen-install: ## Install the Web API key generator tool system-wide
	go install ./cmd/webapi_keygen

################################################################################
# Web Clients
################################################################################

# Seconds between Wayback Machine requests. The archive throttles by refusing
# connections outright, so raise this rather than retrying harder if a run
# starts stalling.
WAYBACK_DELAY ?= 2.5

.PHONY: fetch-aim-express
fetch-aim-express: ## Mirror the archived AIM Express web clients from the Wayback Machine into $(CLIENT_DIR)
	mkdir -p $(CLIENT_DIR)
	./scripts/grab-gromit.sh -o $(CLIENT_DIR) -d $(WAYBACK_DELAY)
