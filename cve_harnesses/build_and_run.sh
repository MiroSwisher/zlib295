#!/bin/bash
set -e

LLVM_PREFIX=$(brew --prefix llvm)
CC="$LLVM_PREFIX/bin/clang"
SDKROOT=$(xcrun --sdk macosx --show-sdk-path)
LLVM_CXX_LIB="$LLVM_PREFIX/lib/c++"
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
HARNESS_DIR="$PROJECT_DIR/cve_harnesses"

SANITIZE_CFLAGS="-fsanitize=fuzzer-no-link,address -g -O1 -fno-omit-frame-pointer -isysroot $SDKROOT"
SANITIZE_FUZZ="-fsanitize=fuzzer,address -g -O1 -fno-omit-frame-pointer -isysroot $SDKROOT -L$LLVM_CXX_LIB -Wl,-rpath,$LLVM_CXX_LIB"

build_zlib_configure() {
  local src_dir="$1"
  local build_dir="$2"
  echo "=== Building zlib from $src_dir (using configure) ==="
  rm -rf "$build_dir"
  mkdir -p "$build_dir"

  # Copy source to build dir so configure doesn't pollute source
  cp -R "$src_dir"/* "$build_dir/"
  cd "$build_dir"

  # Patch: the old zutil.h defines fdopen(fd,mode) as NULL under TARGET_OS_MAC
  # which conflicts with modern macOS SDK headers. Replace with a guard.
  python3 -c "
import re
with open('zutil.h') as f:
    txt = f.read()
# Replace the TARGET_OS_MAC block's fdopen definition
txt = txt.replace(
    '#      ifndef fdopen\n#        define fdopen(fd,mode) NULL /* No fdopen() */\n#      endif',
    '/* fdopen is available on modern macOS - removed bogus NULL macro */')
with open('zutil.h', 'w') as f:
    f.write(txt)
"

  CC="$CC" CFLAGS="$SANITIZE_CFLAGS" ./configure --static 2>&1 | tail -5
  make -j$(sysctl -n hw.ncpu) libz.a 2>&1 | tail -3
  echo "  Done: $build_dir/libz.a"
  cd "$PROJECT_DIR"
}

build_harness() {
  local harness_src="$1"
  local zlib_build_dir="$2"
  local output_name="$3"

  echo "=== Building $output_name ==="
  $CC $SANITIZE_FUZZ \
    -I"$zlib_build_dir" \
    "$harness_src" \
    "$zlib_build_dir/libz.a" \
    -o "$zlib_build_dir/$output_name"
  echo "  Done: $zlib_build_dir/$output_name"
}

# --- CVE-2022-37434 (zlib v1.2.12) ---
echo ""
echo "======================================"
echo "  CVE-2022-37434 (zlib v1.2.12)"
echo "======================================"
ZLIB_112_BUILD="$PROJECT_DIR/cve_builds/cve-2022-37434"
build_zlib_configure "$PROJECT_DIR/zlib-1.2.12" "$ZLIB_112_BUILD"
build_harness "$HARNESS_DIR/cve_2022_37434_fuzzer.c" "$ZLIB_112_BUILD" "cve_2022_37434_fuzzer"

# --- CVE-2018-25032 (zlib v1.2.11) ---
echo ""
echo "======================================"
echo "  CVE-2018-25032 (zlib v1.2.11)"
echo "======================================"
ZLIB_111_BUILD="$PROJECT_DIR/cve_builds/cve-2018-25032"
build_zlib_configure "$PROJECT_DIR/zlib-1.2.11" "$ZLIB_111_BUILD"
build_harness "$HARNESS_DIR/cve_2018_25032_fuzzer.c" "$ZLIB_111_BUILD" "cve_2018_25032_fuzzer"

echo ""
echo "======================================"
echo "  All builds complete!"
echo "======================================"
echo ""
echo "To run:"
echo "  $ZLIB_112_BUILD/cve_2022_37434_fuzzer corpus_dir"
echo "  $ZLIB_111_BUILD/cve_2018_25032_fuzzer corpus_dir"
