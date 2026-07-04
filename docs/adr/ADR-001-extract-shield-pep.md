# ADR-001: Extract KLShield PEP Into Dedicated Repository

## Status

Accepted

## Context

KLShield is the privileged data-plane enforcement component for Kernloom runtime
network controls. The previous implementation lived in an experimental
monorepo path and was easy to confuse with the Kernloom adapter.

The adapter and PEP have different release, privilege and operational profiles.
The adapter speaks the Kernloom contract. Shield owns the local XDP program,
pinned maps and host-level enforcement behavior.

## Decision

Extract KLShield into `github.com/kernloom/kernloom-shield` as the canonical
PEP repository.

The repository contains:

- the `klshield` userspace CLI;
- the XDP/eBPF source;
- the BPF build;
- repository-local CI and release packaging;
- developer, operator and user documentation.

## Consequences

- `kernloom-adapter-klshield` depends on the Shield CLI/map ABI instead of
  owning the data plane.
- Shield can have a privileged host release process independent of adapter
  contract changes.
- Map ABI changes require coordination with the adapter and KLIQ runtime action
  semantics.
