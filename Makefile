################################################################################
# Build & release helpers
################################################################################

DOCKER_IMAGE_TAG_GO_RELEASER := goreleaser/goreleaser:v2.13.1
# Docker builds cannot load a macOS USB PKCS#11 token. Options: (1) SKIP_CODE_SIGN=1 and skip;
# (2) SIGN_HTTP_URL=http://host.docker.internal:8765 plus `make sign-server` on the host to
# sign via HTTP; (3) run release-sign with host goreleaser (no Docker).
SKIP_CODE_SIGN ?= 1
# When set (e.g. http://host.docker.internal:8765), GoReleaser in Docker calls the host
# sign_server to run PKCS#11 signing on the same bind-mounted dist/ tree.
SIGN_HTTP_URL ?=
SIGN_SERVER_TOKEN ?=
GORELEASER ?= goreleaser

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

.PHONY: config-basic config-ssl config
config-basic: ## Generate basic config file template
	go run ./cmd/config_generator unix config/settings.env basic

config-ssl: ## Generate SSL config file template
	go run ./cmd/config_generator unix config/ssl/settings.env ssl

config: config-basic config-ssl ## Generate all config file templates from Config struct

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

.PHONY: docker-image-stunnel
docker-image-stunnel: ## Build stunnel image pinned to v5.75 / OpenSSL 1.0.2u
	docker build -t ras-stunnel:5.75-openssl-1.0.2u -f Dockerfile.stunnel .

.PHONY: docker-image-certgen
docker-image-certgen: ## Build minimal helper image with openssl & nss tools
	docker build -t ras-certgen:latest -f Dockerfile.certgen .

.PHONY: docker-images
docker-images: docker-image-ras docker-image-stunnel docker-image-certgen

.PHONY: docker-run
docker-run:
	OSCAR_HOST=$(OSCAR_HOST) docker compose up open-oscar-server stunnel

.PHONY: docker-run-bg
docker-run-bg: ## Run Open OSCAR Server in background with docker-compose
	OSCAR_HOST=$(OSCAR_HOST) docker compose up -d open-oscar-server stunnel

.PHONY: docker-run-stop
docker-run-stop: ## Stop Open OSCAR Server docker-compose services
	OSCAR_HOST=$(OSCAR_HOST) docker compose down

.PHONY: run
run: # run the server with plain socket config
	./scripts/run_dev.sh ./config/settings.env

.PHONY: run-ssl
run-ssl: # run the server with ssl socket config
	./scripts/run_dev.sh ./config/ssl/settings.env

.PHONY: run-stunnel
run-stunnel: # run stunnel for SSL termination
	./scripts/run_stunnel.sh ./certs/server.pem

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

################################################################################
# Web API Tools
################################################################################

.PHONY: webapi-keygen
webapi-keygen: ## Build the Web API key generator tool
	go build -o webapi_keygen ./cmd/webapi_keygen

.PHONY: webapi-keygen-install
webapi-keygen-install: ## Install the Web API key generator tool system-wide
	go install ./cmd/webapi_keygen
