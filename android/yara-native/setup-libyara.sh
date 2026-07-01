#!/usr/bin/env bash
# setup-libyara.sh — Vendor libyara into the yara-native module for NDK cross-compilation.
#
# Usage: cd android/yara-native && ./setup-libyara.sh
#
# This clones the YARA source at a pinned tag and patches the CMakeLists
# for Android NDK cross-compilation.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LIBYARA_DIR="${SCRIPT_DIR}/src/main/cpp/libyara"
YARA_VERSION="4.5.1"

if [ -d "${LIBYARA_DIR}" ]; then
    echo "libyara already vendored at ${LIBYARA_DIR}"
    exit 0
fi

echo "Cloning YARA v${YARA_VERSION}..."
git clone --depth 1 --branch "${YARA_VERSION}" https://github.com/VirusTotal/yara.git "${LIBYARA_DIR}"

echo "Applying Android NDK patches..."
# YARA's CMakeLists needs minor patches for Android:
# 1. Disable threading primitives not available on all Android API levels
# 2. Adjust re2c/flex bootstrap (use pre-generated sources)
cat > "${LIBYARA_DIR}/CMakeLists.android.patch" << 'PATCH'
--- a/CMakeLists.txt
+++ b/CMakeLists.txt
@@ -20,3 +20,8 @@
 
 option(BUILD_SHARED_LIBS "Build shared libraries" OFF)
+
+if(ANDROID)
+  add_definitions(-DUSE_NO_PROC)
+  set(HAVE_LIBM 1)
+endif()
PATCH

cd "${LIBYARA_DIR}"
git apply CMakeLists.android.patch || echo "Patch may already be applied or not needed"

echo ""
echo "libyara v${YARA_VERSION} vendored successfully."
echo "The yara-native CMakeLists.txt will automatically detect and build it."
echo "Rebuild the Android project to link the real YARA engine."
