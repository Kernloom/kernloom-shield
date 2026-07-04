# Kernloom Shield

Kernloom Shield is the local enforcement point for Kernloom runtime networking.
It contains the privileged userspace CLI (`klshield`) and the XDP/eBPF program
that enforces allow, deny, rate-limit and edge-level rules on Linux interfaces.

The Shield repository is deliberately separate from `kernloom-adapter-klshield`:
the adapter translates Kernloom runtime actions into local Shield operations,
while this repository owns the packet-processing data plane and its pinned BPF
map ABI.

## Status

This repository is the extracted KLShield PEP from the former experimental
Shield tree. The first extracted scope keeps the existing CLI and XDP program
intact, adds repository-local build automation, and documents the operational
boundary.

## Layout

- `cmd/klshield/`: privileged userspace CLI for attach/detach, map updates,
  telemetry and local inspection.
- `bpf/`: XDP/eBPF program and BPF build Makefile.
- `bpf/include/vmlinux.h`: checked-in BTF-derived kernel type header used by
  the current BPF build.
- `docs/`: developer, operator and user guidance.

## Build

Prerequisites on Linux:

- Go 1.26.4
- `clang`/`llvm` with BPF target support
- libbpf headers (`bpf_helpers.h`, `bpf_endian.h`)

Common commands:

```sh
make test
make vet
make build
make bpf
make dist
```

The userspace binary is written to `bin/klshield`. The BPF object is written to
`bpf/out/xdp_kernloom_shield.bpf.o`.

## Local Operation

`klshield` needs elevated privileges for XDP attach/detach and pinned BPF map
access. On a development host:

```sh
sudo ./bin/klshield attach-xdp -iface eth0
sudo ./bin/klshield status
sudo ./bin/klshield set-default-rl -rate 1000 -burst 2000
sudo ./bin/klshield add-deny-ip 198.51.100.23
sudo ./bin/klshield top-src -n 10 -by droprl
sudo ./bin/klshield detach-xdp -iface eth0
```

The default object path for `attach-xdp` is
`bpf/out/xdp_kernloom_shield.bpf.o`, matching `make bpf`.

For production host hardening, use the operations runbook and admin templates:

- `docs/operations/host-hardening.md`
- `docs/operations/host-integration-test.md`
- `docs/admin-template/klshield.service`
- `docs/admin-template/kernloom-shield.sysusers`
- `docs/admin-template/kernloom-shield.tmpfiles`

## Kernloom Boundary

Kernloom Core and KLIQ decide what runtime actions should exist. The
KLShield adapter is the control-plane integration layer. Kernloom Shield is the
local PEP and should stay focused on deterministic local enforcement:

- maintain the pinned BPF map ABI;
- attach, detach and inspect the XDP program;
- perform local allow/deny/rate-limit/edge updates;
- expose local telemetry for debugging and adapter conformance.

It must not become a policy compiler, registry consumer, proof issuer or
Kernloom control-plane service.

## Licensing

This repository contains components under different licenses:

- `bpf/`: GPL-2.0-only
- Go userspace, docs and repository automation: MPL-2.0

See `LICENSE` and `LICENSES/` for the full licensing map and license texts.
