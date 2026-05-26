#!/usr/bin/env bash
set -euo pipefail

CRATE_NAME="zlicenser-server"
CARGO_REGISTRY_TOKEN="${ZER_CRATES_IO_TOKEN:-}"

check_deps() {
    if ! command -v cargo &>/dev/null; then
        echo "error: cargo not found. Install Rust via https://rustup.rs" >&2
        exit 1
    fi
}

verify_build() {
    echo "==> Verifying crate builds cleanly..."
    cargo check --quiet
    echo "    OK"
}

publish_dry_run() {
    echo "==> Dry-run publish (no upload)..."
    cargo publish --dry-run
    echo "    OK"
}

publish() {
    if [[ -z "$CARGO_REGISTRY_TOKEN" ]]; then
        echo "error: ZER_CRATES_IO_TOKEN is not set." >&2
        echo "       Export it or run: cargo login" >&2
        exit 1
    fi

    echo "==> Publishing ${CRATE_NAME} to crates.io..."
    cargo publish --token "$CARGO_REGISTRY_TOKEN"
    echo "    Published: https://crates.io/crates/${CRATE_NAME}"
}

usage() {
    cat <<EOF
Usage: $0 [command]

Commands:
  check       Verify the crate builds cleanly (default)
  dry-run     Run cargo publish --dry-run without uploading
  publish     Publish to crates.io (requires CARGO_REGISTRY_TOKEN)

Environment:
  ZER_CRATES_IO_TOKEN    API token from https://crates.io/settings/tokens
EOF
}

main() {
    local cmd="${1:-check}"
    check_deps

    case "$cmd" in
        check)    verify_build ;;
        dry-run)  verify_build && publish_dry_run ;;
        publish)  verify_build && publish_dry_run && publish ;;
        help|--help|-h) usage ;;
        *)
            echo "error: unknown command: $cmd" >&2
            usage >&2
            exit 1
            ;;
    esac
}

main "$@"
