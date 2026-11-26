#!/usr/bin/env bash
# Source this file; don't replace HOME or other shared workspace identity.
LOFT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
LOFT_TOOLS_ROOT="${LOFT_TOOLS_ROOT:-${HOME}/.local/share/loft-mobile}"
export ANDROID_HOME="${LOFT_ANDROID_SDK_ROOT:-${LOFT_TOOLS_ROOT}/android-sdk}"
export ANDROID_SDK_ROOT="${ANDROID_HOME}"
export ANDROID_NDK_HOME="${ANDROID_HOME}/ndk/28.2.13676358"
export JAVA_HOME="${JAVA_HOME:-/usr/lib/jvm/java-21-openjdk-amd64}"
LOFT_GO_BIN="${LOFT_GO_BIN:-${HOME}/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.27.4.linux-amd64/bin}"
export PATH="${HOME}/.cargo/bin:${LOFT_GO_BIN}:${ANDROID_HOME}/platform-tools:${JAVA_HOME}/bin:${PATH}"
# rustup selects by working directory, not Cargo's --manifest-path. Pin here
# so root/CI native commands use the same toolchain as the Rust workspace.
export RUSTUP_TOOLCHAIN=1.100.0
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
export GOMAXPROCS="${GOMAXPROCS:-2}"
export GOTOOLCHAIN=local
export GOFLAGS="${GOFLAGS:-} -p=2"
