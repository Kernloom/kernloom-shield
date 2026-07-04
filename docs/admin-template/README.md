# Kernloom Shield Admin Template

Use this template when documenting a host-specific Shield deployment.

## Host

- Environment:
- Interface:
- Shield version:
- BPF object checksum:
- Operator contact:

## Privileges

- Service account:
- Capabilities:
- BPF filesystem mount:
- Change window:

## Runtime Defaults

- Default rate limit:
- Event sampling mask:
- Tuple enforcement mode:
- Break-glass procedure:

## Rollback

```sh
sudo ./bin/klshield status
sudo ./bin/klshield detach-xdp -iface <iface>
```

Record any pinned-map cleanup separately. Do not clear maps on a managed host
unless the current runtime action leases have been reconciled.
