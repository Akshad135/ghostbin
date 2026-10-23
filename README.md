# ghostbin

> A fast, self-hosted, private-first ghostbin with syntax highlighting, file attachments, and End-to-End Encryption (E2EE), powered by Rust and React.

## Features

- Backend powered by Rust and SQLite
- Syntax highlighting for 50+ languages via [Shiki](https://shiki.style)
- File attachments with configurable size limits
- End-to-End Encryption (E2EE) derived from your auth passphrase
- Single-user authentication (no accounts needed)
- Burn-after-read and view-counted encrypted sharing
- Pin important pastes to the top
- Zero tracking (no analytics, no tracking cookies, self-hosted fonts)

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

## Getting Started (Podman)

You can run ghostbin by pulling the pre-built image or by building it yourself.

### Using Pre-built Image

```bash
podman run -d \
  -p 127.0.0.1:8788:8788 \
  -v ghostbin-data:/app/data \
  docker.io/akshad135/ghostbin
```

On first visit you choose a passphrase in the browser. It derives both the
login key and the E2EE vault key — the server never sees it, so it is not
configured via environment variables.

### Build from Source

1. Clone the repository:

   ```bash
   git clone https://github.com/Akshad135/ghostbin.git
   cd ghostbin
   ```

2. Start the services via Podman Compose:

   ```bash
   podman-compose up -d
   ```

3. Open `http://localhost:8788` in your browser.

> **Note:** `MAX_TEXT_SIZE`, `MAX_FILE_SIZE`, `ALLOWED_ORIGINS`, `TRUSTED_PROXIES`, `HSTS_ENABLED`, `SETUP_TOKEN`, and `RESET_DB` can be defined in an `.env` file in the root directory (see [.env.example](.env.example)). The browser enforces the size caps with build-time values — see `.env.example` if you raise the server limits.

## Local Build

If you want to run the project natively you will need **Node.js** and **Rust**.

### Prerequisites

- Node.js & npm
- Rust (`cargo`)

### Setup

```bash
# 1. Install frontend dependencies
npm install

# 2. Start the Rust backend (runs on :8788 by default)
npm run dev:backend

# 3. Start the Vite frontend in a new terminal
npm run dev
```

Visit `http://localhost:5173` to see the frontend. API requests are automatically proxied to the backend.

## Configuration

Branding is configured in [`config.yaml`](config.yaml) (committed to the repo). Edit it to customize your instance (app name, description, icons, etc).

Backend environment variables (see [.env.example](.env.example) for the full list):

- `MAX_TEXT_SIZE`: Max size in bytes for a text paste (Default: 512 KB).
- `MAX_FILE_SIZE`: Max size in bytes for a single file attachment (Default: 50 MB).
- `ALLOWED_ORIGINS`: Your public origin, e.g. `https://paste.mydomain.com`. Locks down CORS; leave unset only for local dev.
- `TRUSTED_PROXIES`: Comma-separated IPs/CIDRs of your reverse proxy. When set, rate limits use the real client IP from `X-Forwarded-For`; otherwise the header is ignored.
- `HSTS_ENABLED`: Set to `1` when the app is served over TLS end-to-end to add `Strict-Transport-Security`.
- `BIND_ADDR`: Listen address (Default: `0.0.0.0`). Use `127.0.0.1` for bare-metal deploys behind a local proxy.
- `RESET_DB`: `1` wipes only an incompatible (old-model) database; `force` wipes even the current schema (e.g. to reclaim an instance whose setup was squatted). Destroys all data — back up first.
- `SETUP_TOKEN`: Optional shared secret required to claim a fresh instance via the setup dialog. Set it before exposing the server publicly so a scanner cannot squat the one-time setup.

> **Icons**: Drop your own images into `public/` and update `config.yaml`. The bundled ghost icon is used by default and adapts its color to the active theme.

## Security

The server sends `Content-Security-Policy` (self-only sources, `wasm-unsafe-eval` for the Argon2id KDF), `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, `Permissions-Policy`, and `X-Frame-Options: DENY` on every response. API, paste, share, and file responses are `Cache-Control: no-store`.

Rate limits: login is throttled per IP (5 failures/minute) and per account (30 failures/minute across all IPs). Share unlock attempts are limited to 5 per minute per IP and paste, with an exponential lockout that doubles on repeated attempts and caps at 15 minutes. All limits return `429` with `Retry-After`.

### Deployment behind a reverse proxy

Do not publish the app port on all interfaces without TLS. Run the backend bound to localhost (or a private container network) and terminate TLS with Caddy/nginx/Traefik:

- Set `ALLOWED_ORIGINS` to your public origin.
- Set `TRUSTED_PROXIES` to the proxy's CIDR so rate limiting sees real client IPs.
- Set `HSTS_ENABLED=1` once HTTPS works end-to-end.
- Pass `X-Forwarded-For` from the proxy (nginx: `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;`).

### Backups

Use `scripts/backup.sh` — it snapshots the database with `VACUUM INTO` (safe while the server runs; never copy the live SQLite file, its WAL sidecars make a plain copy corruptible) and archives the uploads directory:

```bash
scripts/backup.sh ./data ./backups
```

## License

This project is licensed under the [MIT License](LICENSE).
