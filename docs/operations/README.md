# Kernloom Shield Operations

KLShield is privileged Linux networking software. Treat it as host-level
enforcement infrastructure.

## Prerequisites

- Linux host with XDP-capable network interface.
- Mounted BPF filesystem at `/sys/fs/bpf`.
- `CAP_NET_ADMIN` and BPF-related privileges for attach/detach and map access.
- BPF object built with `make bpf`.

## Start

```sh
make build
make bpf
sudo ./bin/klshield attach-xdp -iface eth0
sudo ./bin/klshield status
```

Use `-force` only on development hosts when replacing an existing XDP program on
the same interface:

```sh
sudo ./bin/klshield attach-xdp -iface eth0 -force
```

## Inspect

```sh
sudo ./bin/klshield status
sudo ./bin/klshield stats
sudo ./bin/klshield top-src -n 20 -by pkts
sudo ./bin/klshield list-deny
sudo ./bin/klshield list-rl
sudo ./bin/klshield events
```

Pinned maps are stored below `/sys/fs/bpf/kernloom_*`. The CLI reuses pinned
maps across reloads where possible.

For production installs, apply the host hardening runbook in
`docs/operations/host-hardening.md`, run the host integration checklist in
`docs/operations/host-integration-test.md`, and adapt the
systemd/sysusers/tmpfiles templates under `docs/admin-template/`.

## Stop

```sh
sudo ./bin/klshield detach-xdp -iface eth0
```

If exactly one Shield XDP link is attached, `detach-xdp` can auto-detect it:

```sh
sudo ./bin/klshield detach-xdp
```

## Recovery Notes

- `status` shows attached interfaces, default rate-limit state, deny counts and
  tuple enforcement mode.
- `reset` clears deny and rate-limit entries, but should be used carefully on a
  managed host because it removes active enforcement state.
- Keep the Shield binary and BPF object version aligned. The userspace structs
  must match the loaded BPF maps.
- Keep rollback artifacts for the previous BPF object and binary. Do not clear
  pinned maps until KLIQ lease reconciliation confirms no managed runtime action
  depends on them.
