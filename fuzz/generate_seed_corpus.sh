#!/bin/bash
# Generate seed corpus files for the zlib fuzz harnesses.
# Run from the build directory after building zlib:
#   bash ../fuzz/generate_seed_corpus.sh
#
# Creates corpus directories with small valid zlib/gzip/raw deflate streams
# and some interesting edge cases.

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="${1:-.}"

echo "Generating seed corpus in $BUILD_DIR/corpus/..."

# Create corpus directories per fuzzer
for dir in inflate uncompress compress deflate_roundtrip; do
  mkdir -p "$BUILD_DIR/corpus/$dir"
done

# Helper: produce a zlib-compressed blob from a string
zlib_compress() {
  printf '%s' "$1" | python3 -c "
import sys, zlib
data = sys.stdin.buffer.read()
sys.stdout.buffer.write(zlib.compress(data, $2))
"
}

# Helper: produce a gzip-compressed blob from a string
gzip_compress() {
  printf '%s' "$1" | python3 -c "
import sys, gzip, io
data = sys.stdin.buffer.read()
buf = io.BytesIO()
with gzip.GzipFile(fileobj=buf, mode='wb', compresslevel=$2) as f:
    f.write(data)
sys.stdout.buffer.write(buf.getvalue())
"
}

# Helper: produce raw deflate (no header/trailer)
raw_deflate() {
  printf '%s' "$1" | python3 -c "
import sys, zlib
data = sys.stdin.buffer.read()
co = zlib.compressobj($2, zlib.DEFLATED, -15)
sys.stdout.buffer.write(co.compress(data) + co.flush())
"
}

# --- Generate seed inputs ---

# Small strings at different compression levels
STRINGS=(
  "hello"
  "AAAAAAAAAAAAAAAA"
  "The quick brown fox jumps over the lazy dog"
  ""
  "$(python3 -c 'import os; import sys; sys.stdout.buffer.write(os.urandom(64))' | base64)"
  "$(python3 -c 'print("x" * 4096)')"
)

i=0
for s in "${STRINGS[@]}"; do
  for level in 0 1 6 9; do
    # Zlib format
    zlib_compress "$s" "$level" > "$BUILD_DIR/corpus/inflate/zlib_${i}_l${level}.bin" 2>/dev/null || true
    zlib_compress "$s" "$level" > "$BUILD_DIR/corpus/uncompress/zlib_${i}_l${level}.bin" 2>/dev/null || true

    # Gzip format
    gzip_compress "$s" "$level" > "$BUILD_DIR/corpus/inflate/gzip_${i}_l${level}.bin" 2>/dev/null || true

    # Raw deflate
    raw_deflate "$s" "$level" > "$BUILD_DIR/corpus/inflate/raw_${i}_l${level}.bin" 2>/dev/null || true
  done
  i=$((i + 1))
done

# For inflate_fuzzer: prepend 2-byte parameter header (window_bits selector + flush selector)
mkdir -p "$BUILD_DIR/corpus/inflate_with_header"
for f in "$BUILD_DIR/corpus/inflate"/*.bin; do
  base=$(basename "$f")
  # Window bits selector byte + flush selector byte + compressed data
  # 0 = raw (-15), 1 = zlib (15), 2 = gzip (31), 3 = auto (47)
  for wb in 0 1 2 3; do
    printf "\\x$(printf '%02x' $wb)\\x00" | cat - "$f" \
      > "$BUILD_DIR/corpus/inflate_with_header/${wb}_${base}" 2>/dev/null || true
  done
done

# For deflate_roundtrip_fuzzer: prepend 4-byte parameter header + payload
mkdir -p "$BUILD_DIR/corpus/deflate_roundtrip"
for s in "${STRINGS[@]}"; do
  for level in 0 1 6 9; do
    for wbits in 9 12 15; do
      # 4 param bytes: level, wbits_offset, mem_level, strategy
      printf "\\x$(printf '%02x' $level)\\x$(printf '%02x' $((wbits - 9)))\\x07\\x00" \
        | cat - <(printf '%s' "$s") \
        > "$BUILD_DIR/corpus/deflate_roundtrip/rt_${i}_l${level}_w${wbits}.bin" 2>/dev/null || true
      i=$((i + 1))
    done
  done
done

# For compress_fuzzer: prepend 3-byte header + payload (need >= 10 bytes total)
mkdir -p "$BUILD_DIR/corpus/compress"
for s in "${STRINGS[@]}"; do
  printf "\\x06\\x08\\x00%s" "$s" > "$BUILD_DIR/corpus/compress/seed_${i}.bin" 2>/dev/null || true
  i=$((i + 1))
done

echo "Seed corpus generated."
echo "  inflate_with_header: $(ls "$BUILD_DIR/corpus/inflate_with_header" 2>/dev/null | wc -l) files"
echo "  uncompress:          $(ls "$BUILD_DIR/corpus/uncompress" 2>/dev/null | wc -l) files"
echo "  compress:            $(ls "$BUILD_DIR/corpus/compress" 2>/dev/null | wc -l) files"
echo "  deflate_roundtrip:   $(ls "$BUILD_DIR/corpus/deflate_roundtrip" 2>/dev/null | wc -l) files"
