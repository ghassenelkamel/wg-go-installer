# Security Policy

## Sensitive Files

This project generates private WireGuard material at runtime. Never commit or publish:

- `clients/`
- `clients-full/`
- `clients-private/`
- `clients.backup.*/`
- `client-backups/`
- `wg-data/`
- `wg-state/`
- `wg-client-data/`
- generated `*.conf` files from a real server

The `.gitignore` file excludes these paths by default.

## If A Secret Is Published

If a real client config or server state file is pushed publicly:

1. Treat all exposed WireGuard private keys and preshared keys as compromised.
2. Revoke exposed clients.
3. Rotate the server private key if `wg-state/params.json` or `wg-data/params` was exposed.
4. Regenerate and redistribute client configs.
5. Remove the secret from Git history before republishing.

## Reporting Issues

Open a private security advisory or contact the maintainer directly for vulnerabilities that could expose keys, bypass routing isolation, or weaken the kill switch.
