#!/usr/bin/env bash
set -euo pipefail

target="${1:-$(rustc -vV | awk '/^host:/ { print $2 }')}"
packages="$(cargo tree --locked --target "$target" -e normal,build,dev --prefix none --format '{p}' | awk '{print $1}' | sort -u)"
while IFS= read -r package; do
    case "$package" in
        cc|cmake|vcpkg|openssl|openssl-sys|dbus|dbus-sys|libdbus-sys|libz-sys|zstd-sys|zxing-cpp|zxing-cpp-sys|zbar-sys|opencv|opencv-binding-generator|dav1d-sys|ravif)
            printf 'Disallowed native/compiler dependency for %s: %s\n' "$target" "$package" >&2
            exit 1
            ;;
    esac
done <<< "$packages"
printf 'Dependency audit passed for %s (including build and dev dependencies).\n' "$target"
cargo tree --locked --target "$target" -e features -i image
