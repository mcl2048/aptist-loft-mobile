#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "$0")/env.sh"
test -f "${LOFT_ROOT}/loft-android/app/build/generated/gomobile/loft-engine.aar"
test -f "${LOFT_ROOT}/loft-android/app/build/generated/jniLibs/arm64-v8a/libloft_ffi.so"
python3 "${LOFT_ROOT}/scripts/run_gradle.py" -p "${LOFT_ROOT}/loft-android" --no-daemon --max-workers=2 :ui-foundation:test :app:testReleaseUnitTest :app:lintRelease :app:assembleRelease
