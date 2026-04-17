# Development public key (safe to commit — this is the verifier, not the signer)
DEV_PUBLIC_KEY := xsBLUAYPPViUuMxoK6EOHxeUoxaishXba9DU+5ktZBk=

LDFLAGS := -s -w \
	-X github.com/leredteam/awsdeny/cmd.version=dev \
	-X github.com/leredteam/awsdeny/license.publicKeyB64=$(DEV_PUBLIC_KEY)

.PHONY: build test lint clean dev-license functional

build:
	go build -ldflags '$(LDFLAGS)' -o awsdeny .

test:
	go test ./...

lint:
	go vet ./...

# Generate a dev Pro license key (requires DEV_PRIVATE_KEY env var)
dev-license:
	@if [ -z "$$DEV_PRIVATE_KEY" ]; then echo "Set DEV_PRIVATE_KEY env var (see CONTRIBUTING docs)" >&2; exit 1; fi
	@go run . license generate \
		--private-key "$$DEV_PRIVATE_KEY" \
		--email "dev@localhost" \
		--tier pro \
		--days 365

functional: build
	bash test_functional.sh

clean:
	rm -f awsdeny
