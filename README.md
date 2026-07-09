# wg-go-installer

Docker-friendly WireGuard server manager and Linux client helper written in Go.

This project is designed for a small personal VPN server where clients are managed from an interactive menu or CLI, generated configs are stored on the server, and optional AdGuard Home DNS can be used through the VPN address. No Bash scripts are required for normal usage.

## What Do I Run?

On the VPN server/VPS, use `wg-go-installer`:

```bash
cd ~/wg-go-installer
docker compose run --rm -it --entrypoint /usr/local/bin/wg-go-installer wg
```

This opens the server menu. Use it to install the server, add clients, show QR codes, export configs, monitor peers, revoke clients, and regenerate configs.

On your Linux laptop/desktop client, use `wg-client`:

```bash
docker compose --profile client run --rm -it wg-client
```

This opens the client menu. Use it to import a `.conf` file, connect, disconnect, check DNS/leaks, and test the kill switch.

Phone/tablet clients do not need this repo. Add a client on the server, show the QR code, then scan it with the official WireGuard app.

## Server Menu

When you SSH into the server, run:

```bash
cd ~/wg-go-installer
docker compose run --rm -it --entrypoint /usr/local/bin/wg-go-installer wg
```

You should see:

```text
┌────────────────────────────────────────────────────┐
│ wg-go-installer - SERVER MODE                      │
├────────────────────────────────────────────────────┤
│ Run this on the VPN server/VPS, not client devices │
│ Typical flow: 1 install -> 3 add -> 5 scan QR      │
├────────────────────────────────────────────────────┤
│ 1) Install & bring up server                       │
│ 2) Bring server up (saved)                         │
│ 3) Add a new client                                │
│ 4) List clients                                    │
│ 5) Show client QR                                  │
│ 6) Show client config                              │
│ 7) Export client config                            │
│ 8) View server status                              │
│ 9) Monitor clients (live)                          │
│10) Edit client                                     │
│11) Revoke client                                   │
│12) Regenerate endpoint/DNS in configs              │
│13) Generate FULL and PRIVATE profile variants      │
│14) Uninstall/cleanup                               │
│15) Exit                                            │
└────────────────────────────────────────────────────┘
Type the number, or 'h' for help, 'b' to redisplay, 'q' to quit.
Action [1-15 | h=help | b=back | q=quit]:
```

Recommended first-time server flow:

1. Choose `1` to install and bring up WireGuard.
2. Choose `3` to add a client, for example `phone` or `laptop`.
3. Choose `5` to show a QR code for a phone, or `6`/`7` to copy/export the `.conf` file.
4. Choose `8` to verify server status.
5. Choose `9` to watch handshakes and traffic when clients connect.

Recommended returning-server flow:

1. Run `docker compose run --rm wg up` after reboot or deployment.
2. Run the menu when you need to add, view, edit, export, or revoke clients.

## Features

- Interactive server menu for install, client management, QR display, config export, status, monitoring, edit, and revoke.
- Non-interactive CLI for automation and systemd boot services.
- Restores saved peers on `up`, so a reboot or Docker restart reloads all clients from state.
- Generates full-tunnel and private/split-tunnel client profile variants.
- Regenerates endpoint, DNS, and `AllowedIPs` in generated configs without shell scripts.
- Docker Compose workflow for server-side WireGuard management.
- Optional Linux client helper with menu, connect/disconnect, DNS binding, leak checks, and kill-switch test.
- Public-repo safe defaults: generated private keys, client configs, runtime state, caches, and binaries are ignored by Git.

## Architecture

```text
wg-go-installer
├── main.go                  # server manager: install, up, add/list/show/edit/revoke/status
├── cmd/wg-client/main.go    # Linux client helper
├── Dockerfile               # server manager image
├── Dockerfile.client        # client helper image
├── docker-compose.yml       # server and optional client services
└── examples/                # safe placeholder configs/templates
```

Runtime directories are intentionally ignored and should not be committed:

```text
clients/
clients-full/
clients-private/
clients.backup.*/
client-backups/
wg-data/
wg-state/
wg-client-data/
```

These directories contain private keys, preshared keys, server private keys, or generated client files.

## Requirements

Server:

- Linux with WireGuard kernel support or a userspace backend.
- Docker and Docker Compose.
- `/dev/net/tun` available.
- Host firewall/NAT configured for forwarding if `WG_SKIP_IPTABLES=1` is used.
- UDP `51820` open to clients.

Linux client helper:

- `wg-quick`, `wg`, `iproute2`, `iptables` or `nft`, `curl`, and `dig`.
- `sudo` permissions for WireGuard and firewall operations.

## Quick Start: Server

Build and run the server manager:

```bash
docker compose build wg
docker compose run --rm -it wg
```

Equivalent Makefile shortcut:

```bash
make docker-build
make server-menu
```

The numbered menu includes:

```text
1) Install & bring up server
2) Bring server up (saved)
3) Add a new client
4) List clients
5) Show client QR
6) Show client config
7) Export client config
8) View server status
9) Monitor clients (live)
10) Edit client
11) Revoke client
12) Regenerate endpoint/DNS in configs
13) Generate FULL and PRIVATE profile variants
14) Uninstall/cleanup
15) Exit
```

Bring up the saved server state non-interactively:

```bash
docker compose run --rm wg up
```

Equivalent shortcut:

```bash
make server-up
```

List clients:

```bash
docker compose run --rm wg list
```

Show server status:

```bash
docker compose run --rm wg status
```

Show a QR code:

```bash
docker compose run --rm wg show-qr --name PC_Kagha
```

Show a client config:

```bash
docker compose run --rm wg show-config --name PC_Kagha
```

## Endpoint And DNS Regeneration

After moving a server or changing DNS, rewrite generated configs:

```bash
docker compose run --rm wg regenerate-configs --endpoint-host vpn.example.com --endpoint-port 51820 --client-dns 10.66.66.1
docker compose run --rm wg generate-profiles --endpoint-host vpn.example.com --endpoint-port 51820 --client-dns 10.66.66.1
```

If `--endpoint-host` is omitted, the Go command reads it from saved params.

Profile types:

- `clients/`: default full-tunnel configs.
- `clients-full/`: explicit full-tunnel variants.
- `clients-private/`: split/private variants for only VPN subnet routing.

## Running At Boot

Recommended systemd behavior is to run the saved state on boot:

```ini
[Unit]
Description=Bring up WireGuard via wg-go-installer
Requires=docker.service
After=network-online.target docker.service

[Service]
Type=oneshot
RemainAfterExit=true
WorkingDirectory=/home/nixos-server/wg-go-installer
ExecStart=/usr/bin/docker compose run --rm wg up

[Install]
WantedBy=multi-user.target
```

On NixOS, model the same behavior declaratively with a oneshot service.

## Linux Client Helper

Build the client helper image:

```bash
docker compose --profile client build wg-client
```

Run the client helper menu:

```bash
docker compose --profile client run --rm -it wg-client
```

Equivalent shortcut:

```bash
make client-menu
```

Direct host binary usage:

```bash
go build -o wg-client ./cmd/wg-client
./wg-client -config /path/to/wg0-client.conf
```

The client helper can:

- Import a config.
- Connect and run leak checks.
- Disconnect and clean DNS/firewall state.
- Show status.
- Run a kill-switch self-test.

Client setup flow:

1. On the server, add a client with menu option `3`.
2. For a phone/tablet, show the QR with menu option `5` and scan it in the WireGuard app.
3. For a Linux laptop/desktop, export or copy the `.conf`, then run `wg-client` on the client machine.
4. In `wg-client`, choose `1` to import the config.
5. Choose `2` to connect and run checks.
6. Choose `3` to disconnect.

## Development

Run tests:

```bash
go test ./...
```

Or:

```bash
make test
```

Format code:

```bash
gofmt -w main.go cmd/wg-client/main.go main_test.go
```

Build images:

```bash
docker compose build wg
docker compose --profile client build wg-client
```

Or:

```bash
make docker-build
make docker-build-client
```

## License

MIT. See `LICENSE`.
