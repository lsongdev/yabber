# Version defaults to the git description; CI passes a date such as 2026.10.22.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
TAGS    ?=
LDFLAGS := -s -w -X main.version=$(VERSION)
GOFLAGS := -trimpath -tags '$(TAGS)'
DIST    := dist

# GOOS/GOARCH[/GOARM or GOMIPS]. MIPS routers usually lack an FPU.
PLATFORMS := \
	linux/amd64 \
	linux/arm64 \
	linux/arm/7 \
	linux/arm/6 \
	linux/mips/softfloat \
	linux/mipsle/softfloat \
	linux/riscv64 \
	darwin/amd64 \
	darwin/arm64 \
	freebsd/amd64 \
	windows/amd64 \
	windows/arm64

.PHONY: build test test-ui dist clean $(PLATFORMS)

build:
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(DIST)/yabber ./cmd/yabber

test:
	go vet ./...
	go vet -tags worker ./...
	go test -race ./...

# The form preservation tests use Node's built-in runner; no npm install.
test-ui:
	node --test web/test/*.test.mjs

# Release files: binaries, the installer and service definitions, all
# covered by SHA256SUMS, which is signed when YABBER_SIGNING_KEY holds the
# release key, so updates can be verified even when served by a mirror.
dist: $(PLATFORMS)
	cp install.sh $(DIST)/install.sh
	cp contrib/systemd/yabber.service $(DIST)/yabber.service
	cp contrib/openwrt/yabber.init $(DIST)/yabber.init
	cd $(DIST) && shasum -a 256 yabber_* yabber.init yabber.service install.sh > SHA256SUMS
	@if [ -n "$$YABBER_SIGNING_KEY" ]; then \
		go run ./tools/sign < $(DIST)/SHA256SUMS > $(DIST)/SHA256SUMS.sig; \
	else \
		echo "YABBER_SIGNING_KEY is not set: SHA256SUMS is unsigned"; \
	fi

# Expanded per recipe from the target name, so parallel builds are safe.
os      = $(word 1,$(subst /, ,$@))
arch    = $(word 2,$(subst /, ,$@))
variant = $(word 3,$(subst /, ,$@))
binary  = yabber_$(os)_$(arch)$(if $(variant),_$(if $(filter arm,$(arch)),v)$(variant))$(if $(filter windows,$(os)),.exe)

$(PLATFORMS):
	CGO_ENABLED=0 GOOS=$(os) GOARCH=$(arch) \
		$(if $(filter arm,$(arch)),GOARM=$(variant)) \
		$(if $(filter mips mipsle,$(arch)),GOMIPS=$(variant)) \
		go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(DIST)/$(binary) ./cmd/yabber

clean:
	rm -rf $(DIST)

# The web UI's browser dependencies come from npm (web/ui/package.json).
# node_modules there is committed, exactly as npm ci leaves it, so the Go
# module embeds it and `go get` delivers it. After changing package.json,
# run `make deps` and commit the result; check-deps fails when the
# committed files differ from the lockfile.
.PHONY: deps check-deps
deps:
	npm install --prefix web/ui --no-audit --no-fund

check-deps:
	npm ci --prefix web/ui --no-audit --no-fund
	git diff --exit-code --stat -- web/ui/node_modules
	@test -z "$$(git status --porcelain -- web/ui/node_modules)" || (git status --short -- web/ui/node_modules; exit 1)
