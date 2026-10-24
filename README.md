# ghostbin

> A self-hosted pastebin with end-to-end encryption, syntax highlighting, and file attachments. Rust backend, React frontend, one binary.

All encryption happens in the browser. The server stores only ciphertext and never receives your passphrase. Key derivation, encryption, and decryption all run client-side; the server's job is storage, routing, and enforcing burn rules on data it cannot read.

There is no password recovery: a forgotten passphrase means the stored data is unrecoverable. That is a property of the design, not an oversight.

## Features

- **End-to-end encryption**: client-side AES-256-GCM with Argon2id key derivation; the server only handles ciphertext (see [how it works](docs/e2ee.md))
- **Burn rules**: self-deleting pastes by time or view count, enforced atomically server-side
- **Encrypted sharing**: links protected by two independent secrets (URL fragment + separate code), with nonce-challenge proof and replay protection
- **Encrypted attachments** with configurable size limits
- **18 themes**: syntax highlighting (via [@pierre/highlights](https://diffs.com/highlights)) follows the active palette across 50+ languages
- **Live updates**: tabs stay in sync over a notification-only WebSocket
- **Single binary, single container**: Rust + SQLite, no external database
- **No tracking**: no analytics, no tracking cookies, self-hosted fonts

## How it works

Three short documents with diagrams:

| Doc | What it covers |
|---|---|
| [**End-to-end encryption**](docs/e2ee.md) | How your passphrase becomes keys, why the server can't read anything, and how sharing works with two half-secrets |
| [**Live updates & burns**](docs/live-updates.md) | How tabs stay in sync without leaking content, and how self-deletion is enforced exactly |
| [**Architecture**](docs/architecture.md) | The one-binary design, request security (sessions, CSRF, headers), and the trade-offs |

## Screenshots

<div align="center">

![Tokyo Night Dark](public/themes/dark-tokyo.png)

_Tokyo Night (Dark)_

![Catppuccin Light](public/themes/light-catppuccin.png)

_Catppuccin Latte (Light)_

</div>

<details>
<summary><b>View All 18 Themes</b></summary>

> *Themes ported from [herdr](https://github.com/ogulcancelik/herdr).*

### Dark Themes

- [Catppuccin](public/themes/dark-catppuccin.png)
- [Dracula](public/themes/dark-dracula.png)
- [Gruvbox](public/themes/dark-gruvbox.png)
- [Kanagawa](public/themes/dark-kanagawa.png)
- [Nord](public/themes/dark-nord.png)
- [One Dark](public/themes/dark-one.png)
- [Rosé Pine](public/themes/dark-rose-pine.png)
- [Solarized](public/themes/dark-solarized.png)
- [Terminal](public/themes/dark-terminal.png)
- [Tokyo Night](public/themes/dark-tokyo.png)
- [Vesper](public/themes/dark-vesper.png)

### Light Themes

- [Catppuccin Latte](public/themes/light-catppuccin.png)
- [Gruvbox Light](public/themes/light-gruvbox.png)
- [Kanagawa Lotus](public/themes/light-kanagawa.png)
- [One Light](public/themes/light-one.png)
- [Rosé Pine Dawn](public/themes/light-rose-pine.png)
- [Solarized Light](public/themes/light-solarized.png)
- [Tokyo Day](public/themes/light-tokyo.png)
</details>

## Getting Started

The image works the same under Docker or Podman.

### Using the Pre-built Image

```bash
docker run -d \
  -p 127.0.0.1:8788:8788 \
  -v ghostbin-data:/app/data \
  akshad135/ghostbin
```

```bash
# Podman: identical, just swap the command:
podman run -d \
  -p 127.0.0.1:8788:8788 \
  -v ghostbin-data:/app/data \
  docker.io/akshad135/ghostbin
```

On first visit the browser walks you through setup: you choose a passphrase that derives both your login key and your encryption keys. It is therefore never configured via environment variables, and the server never receives it. Set [`SETUP_TOKEN`](#configuration) first if the server will be reachable by others before you claim it.

### Docker Compose

```bash
git clone https://github.com/Akshad135/ghostbin.git
cd ghostbin
docker compose up -d        # or: podman-compose up -d
```

### Deploy behind a reverse proxy (production)

Do not expose the app port without TLS. Bind it to localhost or a private network and terminate TLS with Caddy/nginx/Traefik:

- `ALLOWED_ORIGINS`: your public origin, e.g. `https://paste.mydomain.com`
- `TRUSTED_PROXIES`: the proxy's CIDR, so rate limiting sees real client IPs (and ignores spoofed `X-Forwarded-For` from anyone else)
- `HSTS_ENABLED=1`: once HTTPS works end-to-end
- Have the proxy send `X-Forwarded-For` (nginx: `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;`) and pass WebSockets through for `/api/events`

## Local Development

Requires **Node.js** and **Rust**.

```bash
npm install            # frontend dependencies

npm run dev:backend    # terminal 1: Rust API on :8788
npm run dev            # terminal 2: Vite dev server on :5173
```

API requests from the dev server are proxied to the backend automatically.

## Configuration

Branding (app name, description, icons) lives in [`config.yaml`](config.yaml). All backend settings are environment variables; see [.env.example](.env.example). Compose users can set them in `.env`:

| Variable | Default | Meaning |
|---|---|---|
| `MAX_TEXT_SIZE` | `524288` (512 KB) | Max size of a text paste. The browser adopts the server's limits automatically at page load. |
| `MAX_FILE_SIZE` | `52428800` (50 MB) | Max size of one attachment |
| `ALLOWED_ORIGINS` | unset (`*`) | Public origin for CORS. **Set this in production.** |
| `TRUSTED_PROXIES` | unset | Comma-separated proxy IPs/CIDRs trusted for `X-Forwarded-For` |
| `HSTS_ENABLED` | `0` | `1` adds Strict-Transport-Security (enable once TLS is end-to-end) |
| `BIND_ADDR` | `0.0.0.0` | Listen address; use `127.0.0.1` for local-only deploys |
| `SETUP_TOKEN` | unset | Shared secret required to claim a fresh instance (protects the one-time setup from scanners) |
| `RESET_DB` | unset | `1` wipes an incompatible old-schema database; `force` wipes even the current one. **Destroys all data.** |

## Security

- **Sessions**: `HttpOnly` + `SameSite=Lax` + `__Host-` cookies with a CSRF double-submit token and same-origin checks on every state-changing request. API responses are always `Cache-Control: no-store`.
- **Headers**: `Content-Security-Policy` (self-only, `wasm-unsafe-eval` for the Argon2id KDF), `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, `Permissions-Policy`, `X-Frame-Options: DENY`.
- **Rate limits**: login 5 failures/min per IP + 30/min per account; share unlock 5/min per IP and paste with an exponential lockout capped at 15 minutes. All return `429` with `Retry-After`.
- The client-side crypto design and its guarantees are described in [docs/e2ee.md](docs/e2ee.md).

### Backups

`scripts/backup.sh` snapshots the database with `VACUUM INTO` (safe while the server runs; never copy the live SQLite file, its WAL sidecars make a plain copy corruptible) and archives the uploads directory:

```bash
# Native deployments with data in ./data:
scripts/backup.sh ./data ./backups

# Container deployments: point it at the volume's mount point:
scripts/backup.sh "$(docker volume inspect ghostbin-data --format '{{.Mountpoint}}')" ./backups
```

(Rootless podman volumes live under `~/.local/share/containers/storage/volumes/` and are readable directly; rootful runtimes need `sudo` for the volume path.)

## License

This project is licensed under the [MIT License](LICENSE).
