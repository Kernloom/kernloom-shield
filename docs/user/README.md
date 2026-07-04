# Kernloom Shield User Guide

`klshield` is the local CLI for inspecting and operating the KLShield PEP.

## Common Commands

```sh
sudo ./bin/klshield status
sudo ./bin/klshield add-deny-ip 198.51.100.23
sudo ./bin/klshield del-deny-ip 198.51.100.23
sudo ./bin/klshield set-default-rl -rate 1000 -burst 2000
sudo ./bin/klshield disable-default-rl
sudo ./bin/klshield top-src -n 10 -by drops
```

## Edge Rules

Edge rules operate on source IP, destination port and protocol:

```sh
sudo ./bin/klshield add-edge-deny -src 198.51.100.23 -port 443 -proto tcp
sudo ./bin/klshield list-edge-deny
sudo ./bin/klshield tuple-enforce on
```

Allow-mode is default-deny for edge tuples. Populate `edge4_allow` before
enabling it:

```sh
sudo ./bin/klshield add-edge-allow -src 198.51.100.23 -port 443 -proto tcp
sudo ./bin/klshield tuple-enforce allow
```

## Relationship To Kernloom

In a managed Kernloom deployment, most Shield operations should be driven by
KLIQ through `kernloom-adapter-klshield`. Direct CLI use is primarily for local
development, break-glass operations and inspection.
