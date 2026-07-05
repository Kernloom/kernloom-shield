# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Kernloom Contributors

GO ?= go
TRIVY ?= trivy
COSIGN ?= cosign
GOVULNCHECK ?= govulncheck
BINDIR ?= bin
DISTDIR ?= dist
IMAGE ?=
KL_SHIELD_BIN := $(BINDIR)/klshield
BPF_OBJ := bpf/out/xdp_kernloom_shield.bpf.o

.PHONY: all build test vet bpf dist checksums sbom vuln-scan govulncheck release-provenance release-sign container-sign release-promote-check release-check clean

all: build bpf

build:
	mkdir -p $(BINDIR)
	$(GO) build -o $(KL_SHIELD_BIN) ./cmd/klshield

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

bpf:
	$(MAKE) -C bpf all

dist: build bpf
	mkdir -p $(DISTDIR)
	cp $(KL_SHIELD_BIN) $(DISTDIR)/klshield
	cp $(BPF_OBJ) $(DISTDIR)/xdp_kernloom_shield.bpf.o

checksums: dist
	sha256sum $(DISTDIR)/klshield $(DISTDIR)/xdp_kernloom_shield.bpf.o > $(DISTDIR)/checksums.txt

release-provenance: checksums
	{ \
		echo "{"; \
		echo "  \"kind\": \"KernloomReleaseProvenance\","; \
		echo "  \"source_commit\": \"$$(git rev-parse HEAD)\","; \
		echo "  \"go_version\": \"$$($(GO) version)\","; \
		echo "  \"checksums\": \"$(DISTDIR)/checksums.txt\""; \
		echo "}"; \
	} > $(DISTDIR)/provenance.json

sbom: dist
	@command -v $(TRIVY) >/dev/null 2>&1 || { echo "trivy is required for SBOM generation"; exit 127; }
	$(TRIVY) fs --format cyclonedx --output $(DISTDIR)/sbom.cdx.json .

vuln-scan:
	@command -v $(TRIVY) >/dev/null 2>&1 || { echo "trivy is required for vulnerability scanning"; exit 127; }
	$(TRIVY) fs --exit-code 1 --severity HIGH,CRITICAL .

govulncheck:
	@command -v $(GOVULNCHECK) >/dev/null 2>&1 || { echo "govulncheck is required"; exit 127; }
	$(GOVULNCHECK) ./...

release-sign: checksums
	@command -v $(COSIGN) >/dev/null 2>&1 || { echo "cosign is required for release signing"; exit 127; }
	$(COSIGN) sign-blob --yes --output-signature $(DISTDIR)/checksums.txt.sig $(DISTDIR)/checksums.txt

container-sign:
	@test -n "$(IMAGE)" || { echo "IMAGE is required for container-sign"; exit 2; }
	@command -v $(COSIGN) >/dev/null 2>&1 || { echo "cosign is required for container signing"; exit 127; }
	$(COSIGN) sign --yes $(IMAGE)

release-promote-check: checksums sbom release-provenance
	test -s $(DISTDIR)/checksums.txt
	test -s $(DISTDIR)/sbom.cdx.json
	test -s $(DISTDIR)/provenance.json

release-check: test vet dist checksums sbom vuln-scan govulncheck release-provenance release-promote-check

clean:
	$(MAKE) -C bpf clean
	rm -rf $(BINDIR) $(DISTDIR)
