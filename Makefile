# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Kernloom Contributors

GO ?= go
BINDIR ?= bin
DISTDIR ?= dist
KL_SHIELD_BIN := $(BINDIR)/klshield
BPF_OBJ := bpf/out/xdp_kernloom_shield.bpf.o

.PHONY: all build test vet bpf dist clean

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

clean:
	$(MAKE) -C bpf clean
	rm -rf $(BINDIR) $(DISTDIR)
