# Kernloom Shield Developer Notes

KLShield is the Kernloom packet enforcement point. Development should preserve a
clear boundary between local enforcement and Kernloom control-plane logic.

## Responsibilities

- Own the XDP/eBPF program and userspace map ABI.
- Keep pinned map names stable unless an explicit migration plan exists.
- Keep CLI operations deterministic and inspectable.
- Keep privileged operations local to this repo.

## Non-Responsibilities

- Do not compile Kernloom authoring intents.
- Do not resolve policy profiles, guardrails or registries.
- Do not issue proofs or aggregate correlation evidence.
- Do not replace `kernloom-adapter-klshield`; the adapter remains the bridge
  from Kernloom runtime actions into Shield map operations.

## Map ABI

Pinned maps live under `/sys/fs/bpf/kernloom_*`. The current userspace CLI
expects these map names and value layouts to match the structs in
`cmd/klshield/klshield.go` and `bpf/xdp_kernloom_shield.bpf.c`.

When changing map names or layouts:

1. Add compatibility or a migration path.
2. Update CLI read/write logic.
3. Update adapter conformance expectations in `kernloom-adapter-klshield`.
4. Document the operational impact.

## Local Checks

```sh
make test
make vet
make build
make bpf
```

`make bpf` requires a Linux BPF toolchain. Unit tests avoid privileged
operations and can run without XDP attachment.
