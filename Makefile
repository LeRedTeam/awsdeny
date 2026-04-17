# Development keypair (NOT for production — use CI secrets for releases)
DEV_PUBLIC_KEY  := xsBLUAYPPViUuMxoK6EOHxeUoxaishXba9DU+5ktZBk=
DEV_PRIVATE_KEY := oLhCWF1xWCjiBk93wZR6j2spOISvUqz7+lCdu/JWvezGwEtQBg89WJS4zGgroQ4fF5SjFqKyFdtr0NT7mS1kGQ==

LDFLAGS := -s -w \
	-X github.com/leredteam/awsdeny/cmd.version=dev \
	-X github.com/leredteam/awsdeny/license.publicKeyB64=$(DEV_PUBLIC_KEY)

.PHONY: build test lint clean dev-license

# Build with dev license key embedded
build:
	go build -ldflags '$(LDFLAGS)' -o awsdeny .

test:
	go test ./...

lint:
	go vet ./...

# Generate a dev Pro license key (valid 1 year)
dev-license:
	@go run . license generate \
		--private-key "$(DEV_PRIVATE_KEY)" \
		--email "dev@localhost" \
		--tier pro \
		--days 365

# Run functional tests
functional: build
	bash test_functional.sh

clean:
	rm -f awsdeny
