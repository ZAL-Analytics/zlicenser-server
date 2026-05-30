# zlicenser-server

Server library and vendor backend for the [zlicenser](https://github.com/zal-analytics/zlicenser) licensing framework.

This is the vendor side of the ecosystem. Vendors self-host the server binary to issue and manage licenses for their software. The library crate can also be embedded directly in an existing application if you'd rather not run a separate server process.

The server handles the four-message license exchange protocol, seat enforcement, hardware binding, revocation, grace period tracking, and hardware transfer requests. It comes with a web dashboard for managing products, licenses, and customers without touching the API directly.

## What's in this repo

```
crates/zlicenser-server/     # library crate (published to crates.io)
apps/zlicenser-server-bin/   # axum server binary with embedded SvelteKit dashboard
bindings/python/             # PyO3 + maturin
bindings/nodejs/             # napi-rs
bindings/go/                 # CGo + cbindgen
migrations/                  # SQL migrations
xtask/                       # build automation
docs/                        # mdBook documentation
```

The library crate is the only thing published to crates.io. Everything else is `publish = false`.

## Features

| Feature | Description | Default |
|---|---|---|
| `http-server` | axum HTTP routes and middleware | yes |
| `storage-sqlite` | SQLite storage backend | yes |
| `storage-postgres` | PostgreSQL storage backend | no |
| `payment-stripe` | Stripe payment integration | no |

SQLite is fine for most self-hosted setups. Switch to `storage-postgres` if you need PostgreSQL for scale or to fit into existing infrastructure. The `storage-postgres` feature uses sqlx's pure-Rust Postgres driver, so there's no `libpq` system dependency.

## Building

Rust toolchain: install via `rustup`. The `rust-toolchain.toml` pins to a specific stable version.

### Ubuntu

```sh
sudo apt install -y libsqlite3-dev python3-dev python3-pip
pip3 install maturin
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs
```

### Fedora

```sh
sudo dnf install -y sqlite-devel python3-devel python3-pip
pip3 install maturin
sudo dnf install -y nodejs
```

SQLite is only needed for the default `storage-sqlite` feature. Node.js is only needed to build the dashboard frontend and the Node.js bindings. Python deps are only needed for the Python bindings.

## Platform

Linux x86_64 only. The client-side components (shim, hardware fingerprinting) depend on Linux kernel interfaces, so the server is only tested and supported on Linux as well. Windows and macOS are not in scope for this project. zlicenser-pro, a future commercial release, may support other operating systems.

## Related repositories

- [zlicenser-protocol](https://github.com/zal-analytics/zlicenser-protocol): shared protocol, crypto, and wire formats
- [zlicenser](https://github.com/zal-analytics/zlicenser): client library and user-facing apps

## License

Apache-2.0, see [LICENSE](LICENSE).
