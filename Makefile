################################################################################
# Build & release helpers
################################################################################

DOCKER_IMAGE_TAG_GO_RELEASER := goreleaser/goreleaser:v2.9.0
DOCKER_RUN_GO_RELEASER := @docker run \
	--env CGO_ENABLED=0 \
	--env GITHUB_TOKEN=$(GITHUB_TOKEN) \
	--rm \
	--volume `pwd`:/go/src/retro-aim-server \
	--workdir /go/src/retro-aim-server \
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

.PHONY: docker-image-ras
docker-image-ras: ## Build Retro AIM Server image
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
	OSCAR_HOST=$(OSCAR_HOST) docker compose up retro-aim-server stunnel

.PHONY: docker-run-bg
docker-run-bg: ## Run Retro AIM Server in background with docker-compose
	OSCAR_HOST=$(OSCAR_HOST) docker compose up -d retro-aim-server stunnel

.PHONY: docker-run-stop
docker-run-stop: ## Stop Retro AIM Server docker-compose services
	OSCAR_HOST=$(OSCAR_HOST) docker compose down

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
