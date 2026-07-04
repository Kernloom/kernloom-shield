# Kernloom Shield Host Hardening

Kernloom Shield is privileged host networking software. Production installs must
make attach, map lifecycle, rollback and uninstall explicit.

## Capabilities

Run attach/detach with the minimum host privileges required by the kernel:

- `CAP_NET_ADMIN` for XDP link attach/detach.
- `CAP_BPF` and `CAP_PERFMON` on kernels that split BPF privileges.
- `CAP_SYS_RESOURCE` only when the host requires locked-memory limits.

Do not run policy authoring, Forge or adapter logic in the Shield process.

## BPF object lifecycle

Install the BPF object as an immutable release artifact:

```sh
install -D -m 0755 bin/klshield /usr/bin/klshield
install -D -m 0644 bpf/out/xdp_kernloom_shield.bpf.o /usr/lib/kernloom-shield/xdp_kernloom_shield.bpf.o
sha256sum /usr/bin/klshield /usr/lib/kernloom-shield/xdp_kernloom_shield.bpf.o
```

Keep the userspace binary and BPF object from the same release. The map ABI is a
host contract; do not mix versions during an upgrade.

## Map pinning lifecycle

Pinned maps live below `/sys/fs/bpf/kernloom_*`. Production upgrades should:

1. record `klshield status`;
2. attach the new object during a change window;
3. verify pinned map compatibility;
4. leave runtime action cleanup to KLIQ/adapter reconciliation.

Only remove pinned maps during uninstall or an explicit break-glass cleanup.

## Rollback

Rollback must detach the new XDP program before reattaching the previous known
good object:

```sh
systemctl stop klshield
install -D -m 0644 /var/lib/kernloom-shield/rollback/xdp_kernloom_shield.bpf.o /usr/lib/kernloom-shield/xdp_kernloom_shield.bpf.o
systemctl start klshield
systemctl status klshield
```

Do not clear maps as part of normal rollback. Active runtime action leases are
reconciled by KLIQ and the KLShield adapter.

## Safe uninstall

```sh
systemctl stop klshield
klshield status
klshield detach-xdp -iface <iface>
```

After confirming no managed leases remain, remove pinned maps deliberately:

```sh
rm -f /sys/fs/bpf/kernloom_*
```

Do not run the cleanup command on a managed host until Forge/KLIQ shows the
runtime actions as expired or revoked.

## Kernel compatibility notes

Record these per host class:

- kernel version and distro;
- NIC driver and XDP mode;
- BTF availability;
- clang/llvm version used for BPF build;
- map pinning path;
- expected interface names.
