.PHONY: build test run whois-init whois-status whois-update whois-update-commit up deploy

build:
	CGO_ENABLED=0 go build -trimpath -o bin/pslmon ./cmd/pslmon

test:
	go test ./...

# --- WHOIS fallback (git submodule third_party/whois-domain-lookup)
whois-init:          ## check out the pinned upstream commit
	scripts/update-whois-upstream.sh --init
whois-status:        ## compare pin with upstream main
	scripts/update-whois-upstream.sh --status
whois-update:        ## move the pin to latest upstream main (review + commit yourself)
	scripts/update-whois-upstream.sh
whois-update-commit: ## move the pin to latest upstream main and commit
	scripts/update-whois-upstream.sh --commit

# --- Docker
up: whois-init       ## build and start using the pinned upstream
	docker compose up -d --build

deploy:              ## pull this repo, sync the submodule to the committed pin, rebuild
	git pull --ff-only
	scripts/update-whois-upstream.sh --init
	docker compose up -d --build
