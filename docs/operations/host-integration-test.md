# Kernloom Shield Host Integration Test

Run this on a disposable or maintenance-window host. The privileged steps attach
an XDP program to a real interface.

## Non-privileged preflight

```sh
go test ./...
go vet ./...
make build
make bpf
test -s bin/klshield
test -s bpf/out/xdp_kernloom_shield.bpf.o
```

Record host compatibility:

```sh
uname -a
clang --version
mount | grep /sys/fs/bpf
ip link show
```

## Privileged smoke test

Set the test interface explicitly:

```sh
export KLSHIELD_IFACE=<iface>
sudo ./bin/klshield attach-xdp -iface "$KLSHIELD_IFACE"
sudo ./bin/klshield status
sudo ./bin/klshield add-deny-ip 198.51.100.23
sudo ./bin/klshield list-deny
sudo ./bin/klshield del-deny-ip 198.51.100.23
sudo ./bin/klshield detach-xdp -iface "$KLSHIELD_IFACE"
```

## Rollback and cleanup check

```sh
sudo ./bin/klshield status
sudo ./bin/klshield detach-xdp -iface "$KLSHIELD_IFACE"
```

Only remove pinned maps after confirming KLIQ has no active managed leases:

```sh
sudo rm -f /sys/fs/bpf/kernloom_*
```
