# Kernloom Shield Examples

Build and attach Shield on a development host:

```sh
make build
make bpf
sudo ./bin/klshield attach-xdp -iface eth0
```

Enable a conservative default rate limit:

```sh
sudo ./bin/klshield set-default-rl -rate 1000 -burst 2000
sudo ./bin/klshield status
```

Block one source immediately:

```sh
sudo ./bin/klshield add-deny-ip 198.51.100.23
sudo ./bin/klshield list-deny
```

Detach after testing:

```sh
sudo ./bin/klshield detach-xdp -iface eth0
```
