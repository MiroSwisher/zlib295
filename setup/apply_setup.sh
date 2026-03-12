#!/bin/bash
# Apply our fuzz overlay and CMake changes to an upstream zlib clone.
# Usage: ./apply_setup.sh [path-to-zlib]
#   If path is omitted, uses ../zlib (clone zlib into the repo's parent dir).

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ZLIB_DIR="${1:-$REPO_DIR/../zlib}"

if [ ! -d "$ZLIB_DIR" ]; then
  echo "Usage: $0 [path-to-zlib]"
  echo "  Zlib directory not found: $ZLIB_DIR"
  echo "  Clone zlib first, e.g.: git clone https://github.com/madler/zlib.git $ZLIB_DIR"
  exit 1
fi

echo "Copying fuzz/ into $ZLIB_DIR/fuzz/ ..."
rm -rf "$ZLIB_DIR/fuzz"
cp -R "$REPO_DIR/fuzz" "$ZLIB_DIR/fuzz"

echo "Applying CMake patch..."
if patch -d "$ZLIB_DIR" -p1 --forward -r - < "$SCRIPT_DIR/zlib_fuzz.patch" 2>/dev/null; then
  echo "Patch applied."
else
  echo "Patch could not be applied (maybe already applied or different zlib version)."
  echo "Add these manually to $ZLIB_DIR/CMakeLists.txt:"
  echo "  1. After 'option(ZLIB_BUILD_STATIC ...)' add:"
  echo "     option(ZLIB_BUILD_FUZZ \"Enable libFuzzer fuzz targets (requires Clang)\" OFF)"
  echo "  2. Before 'add_subdirectory(contrib)' add:"
  echo "     if(ZLIB_BUILD_FUZZ)"
  echo "         add_subdirectory(fuzz)"
  echo "     endif(ZLIB_BUILD_FUZZ)"
fi

echo "Done. Build with: cd $ZLIB_DIR && mkdir -p build && cd build && cmake .. -DZLIB_BUILD_FUZZ=ON -DCMAKE_C_COMPILER=clang && make"
