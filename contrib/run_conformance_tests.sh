#!/usr/bin/env bash
#
# Runs the kernel-bindings-tests conformance suite against conformance-handler.
#
# Downloads the pinned test runner release (verified against a SHA-256 checksum),
# builds the handler in release mode and runs every suite. Extra arguments are
# passed to the runner, e.g.:
#
#   contrib/run_conformance_tests.sh -v
#
# See https://github.com/stringintech/kernel-bindings-tests

set -euo pipefail

VERSION="0.0.4"
BASE_URL="https://github.com/stringintech/kernel-bindings-tests/releases/download/v${VERSION}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HANDLER_DIR="${REPO_ROOT}/conformance-handler"
RUNNER_DIR="${HANDLER_DIR}/.conformance-tests/v${VERSION}"
RUNNER="${RUNNER_DIR}/runner"

case "$(uname -s)" in
    Linux) os="linux" ;;
    Darwin) os="darwin" ;;
    *) echo "Unsupported OS: $(uname -s)" >&2; exit 1 ;;
esac
case "$(uname -m)" in
    x86_64 | amd64) arch="amd64" ;;
    aarch64 | arm64) arch="arm64" ;;
    *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac
platform="${os}_${arch}"

# The release publishes no checksum file, so these are pinned here.
case "${platform}" in
    linux_amd64) expected_sha256="2c9e2262ec5a1698dc9733d339afcf27f48194c99b9ddb2b71c00b01da0c51d2" ;;
    linux_arm64) expected_sha256="8423a94ded3a671f55fae168da0128fb472d8921a5b9ba5b6eae789367c2c559" ;;
    darwin_amd64) expected_sha256="6238e4ce5c131b62e4a335fb4bba3cc8bb0a6abe44924a934b79ab2d95f9447a" ;;
    darwin_arm64) expected_sha256="2e50c8c4a912a7a2bad923d3dbd04d04f48d06e6d67b0c13451b7740989ce708" ;;
esac

sha256() {
    if command -v sha256sum >/dev/null; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

if [ ! -x "${RUNNER}" ]; then
    archive="kernel-bindings-tests_${VERSION}_${platform}.tar.gz"
    tmp="$(mktemp -d)"
    trap 'rm -rf "${tmp}"' EXIT

    echo "Downloading ${archive}"
    curl -sSfL --retry 3 -o "${tmp}/${archive}" "${BASE_URL}/${archive}"

    actual_sha256="$(sha256 "${tmp}/${archive}")"
    if [ "${actual_sha256}" != "${expected_sha256}" ]; then
        echo "Checksum mismatch for ${archive}" >&2
        echo "  expected: ${expected_sha256}" >&2
        echo "  actual:   ${actual_sha256}" >&2
        exit 1
    fi

    tar -xzf "${tmp}/${archive}" -C "${tmp}" runner
    mkdir -p "${RUNNER_DIR}"
    mv "${tmp}/runner" "${RUNNER}"
fi

echo "Building conformance-handler"
cargo build --release --manifest-path "${HANDLER_DIR}/Cargo.toml"

"${RUNNER}" \
    --handler "${HANDLER_DIR}/target/release/conformance-handler" \
    --handler-timeout 30s \
    --timeout 5m \
    "$@"
