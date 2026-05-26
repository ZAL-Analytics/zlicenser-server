# zlicenser-server

Server library and vendor backend for the zlicenser licensing framework.

## Overview

`zlicenser-server` is the vendor side of the zlicenser ecosystem. It includes the library crate for vendors to embed in their own applications, and a ready-to-run axum HTTP server with an embedded SvelteKit dashboard.

## Workspace layout

```
crates/zlicenser-server/     # library crate (crates.io)
apps/zlicenser-server-bin/   # axum server binary with embedded dashboard (publish = false)
bindings/python/             # PyO3 + maturin Python bindings (publish = false)
bindings/nodejs/             # napi-rs Node.js bindings (publish = false)
bindings/go/                 # CGo + cbindgen Go bindings (publish = false)
migrations/                  # SQL migration files
xtask/                       # build automation (publish = false)
docs/                        # mdBook documentation
```

## System dependencies

| Component | Ubuntu | Fedora |
|---|---|---|
| zlicenser-server (default: sqlite + http) | `libsqlite3-dev` | `sqlite-devel` |
| zlicenser-server (postgres feature) | | |
| zlicenser-server-bin | `libsqlite3-dev` | `sqlite-devel` |
| Python bindings | `python3-dev python3-pip` + `pip install maturin` | `python3-devel python3-pip` + `pip install maturin` |
| Node.js bindings | nodejs (>=18) | nodejs (>=18) |
| SvelteKit dashboard | nodejs (>=18) | nodejs (>=18) |

Ubuntu:

```sh
sudo apt install -y libsqlite3-dev python3-dev python3-pip
pip3 install maturin
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs
```

Fedora:

```sh
sudo dnf install -y sqlite-devel python3-devel python3-pip
pip3 install maturin
sudo dnf install -y nodejs
```

Rust toolchain: install via `rustup`, `rust-toolchain.toml` pins to stable. The `storage-postgres` feature uses sqlx's pure-Rust driver, no `libpq` needed.

## Related repositories

- [zlicenser-protocol](https://github.com/zal-analytics/zlicenser-protocol): shared protocol, crypto, and wire formats
- [zlicenser](https://github.com/zal-analytics/zlicenser): client library and user-facing apps

## Features

| Feature | Description | Default |
|---|---|---|
| `http-server` | axum HTTP server routes and middleware | yes |
| `storage-sqlite` | SQLite storage backend via sqlx | yes |
| `storage-postgres` | PostgreSQL storage backend via sqlx | no |
| `payment-stripe` | Stripe payment provider | no |

## License

Apache-2.0, see [LICENSE](LICENSE).
