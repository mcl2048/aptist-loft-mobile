#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "$0")/env.sh"
LOFT_LLVM="${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64/bin"
test "$(go env GOVERSION)" = go1.27.4
LOFT_NATIVE_ABI="${LOFT_NATIVE_ABI:-arm64-v8a}"
case "${LOFT_NATIVE_ABI}" in
  arm64-v8a)
    LOFT_RUST_TARGET=aarch64-linux-android
    LOFT_GOMOBILE_TARGET=android/arm64
    export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="${LOFT_LLVM}/aarch64-linux-android29-clang"
    export CARGO_TARGET_AARCH64_LINUX_ANDROID_RUSTFLAGS="-C link-arg=-Wl,-z,max-page-size=16384"
    export CC_aarch64_linux_android="${LOFT_LLVM}/aarch64-linux-android29-clang"
    export AR_aarch64_linux_android="${LOFT_LLVM}/llvm-ar"
    export RANLIB_aarch64_linux_android="${LOFT_LLVM}/llvm-ranlib"
    test -x "${CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER}"
    ;;
  x86_64)
    # A separate server emulator build; not an advertised production ABI.
    test -n "${LOFT_NATIVE_OUTPUT_ROOT:-}"
    LOFT_TEST_OUTPUT_REAL="$(realpath -m -- "${LOFT_NATIVE_OUTPUT_ROOT}")"
    case "${LOFT_TEST_OUTPUT_REAL}" in
      "${LOFT_ROOT}/tmp/"*) ;;
      *) printf '%s\n' 'Test ABI output must be in the task-owned tmp directory.' >&2; exit 2 ;;
    esac
    LOFT_RUST_TARGET=x86_64-linux-android
    LOFT_GOMOBILE_TARGET=android/amd64
    export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER="${LOFT_LLVM}/x86_64-linux-android29-clang"
    export CARGO_TARGET_X86_64_LINUX_ANDROID_RUSTFLAGS="-C link-arg=-Wl,-z,max-page-size=16384"
    export CC_x86_64_linux_android="${LOFT_LLVM}/x86_64-linux-android29-clang"
    export AR_x86_64_linux_android="${LOFT_LLVM}/llvm-ar"
    export RANLIB_x86_64_linux_android="${LOFT_LLVM}/llvm-ranlib"
    test -x "${CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER}"
    ;;
  *) printf '%s\n' 'Unsupported native ABI.' >&2; exit 2 ;;
esac
LOFT_GENERATED="${LOFT_NATIVE_OUTPUT_ROOT:-${LOFT_ROOT}/loft-android/app/build/generated}"
LOFT_RUST_BUILD_ROOT="${LOFT_RUST_BUILD_ROOT:-${LOFT_ROOT}/loft-core-rust/target}"
mkdir -p "${LOFT_GENERATED}/jniLibs/${LOFT_NATIVE_ABI}" "${LOFT_GENERATED}/uniffi" "${LOFT_GENERATED}/gomobile"
cargo build --manifest-path "${LOFT_ROOT}/loft-core-rust/Cargo.toml" --target-dir "${LOFT_RUST_BUILD_ROOT}" -p loft-ffi --release --target "${LOFT_RUST_TARGET}" --locked
cp "${LOFT_RUST_BUILD_ROOT}/${LOFT_RUST_TARGET}/release/libloft_ffi.so" "${LOFT_GENERATED}/jniLibs/${LOFT_NATIVE_ABI}/"
cargo run --manifest-path "${LOFT_ROOT}/loft-core-rust/Cargo.toml" --target-dir "${LOFT_RUST_BUILD_ROOT}" -p loft-bindgen --locked -- generate "${LOFT_GENERATED}/jniLibs/${LOFT_NATIVE_ABI}/libloft_ffi.so" --language kotlin --config "${LOFT_ROOT}/loft-core-rust/bindings/uniffi.toml" --out-dir "${LOFT_GENERATED}/uniffi" --no-format
cd "${LOFT_ROOT}/loft-vpn-engine-go"
# gomobile uses exec.LookPath; go tool's pinned cache isn't normally in PATH.
# Avoid init's implicit gobind@latest install: use exactly the module-locked tool.
LOFT_GOBIND="$(go tool -n gobind)"
test -x "${LOFT_GOBIND}"
export PATH="$(dirname -- "${LOFT_GOBIND}"):${PATH}"
# sing-tun's actual gVisor stack is feature-gated; a controller-only AAR cannot
# establish the VPN. Keep the tag identical to the Go packet/race test suites.
go tool gomobile bind -tags=with_gvisor -target="${LOFT_GOMOBILE_TARGET}" -androidapi=29 -javapkg=net.aptist.loft -o "${LOFT_GENERATED}/gomobile/loft-engine.aar" ./engine
