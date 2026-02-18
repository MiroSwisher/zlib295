# libFuzzer fuzz targets for zlib

Build and run libFuzzer targets to fuzz zlib's compression and decompression code.

## Build

From the zlib build directory, configure with **Clang** and enable fuzz targets. libFuzzer requires a Clang that ships the fuzzer runtime (e.g. LLVM's Clang).

**Linux** (use system Clang or install `clang`):

```bash
cd /path/to/zlib
mkdir build && cd build
cmake .. -DZLIB_BUILD_FUZZ=ON -DCMAKE_C_COMPILER=clang
make
```

**macOS** – Xcode's Clang usually does *not* include libFuzzer. Use LLVM Clang instead:

```bash
brew install llvm
cd /path/to/zlib && mkdir build && cd build
cmake .. -DZLIB_BUILD_FUZZ=ON -DCMAKE_C_COMPILER=$(brew --prefix llvm)/bin/clang
make
```

Fuzz binaries are produced in `build/fuzz/`:
- **compress_fuzzer** – compress levels, decompress with various zlib headers
- **uncompress_fuzzer** – raw `uncompress()` (decoder stress)

## Run

Run with an optional corpus directory (empty or with seed files). Without a corpus, the fuzzer starts from scratch:

```bash
./fuzz/compress_fuzzer
./fuzz/uncompress_fuzzer
```

With a corpus and output directory for crashes/hangs:

```bash
mkdir -p corpus/compress corpus/uncompress
./fuzz/compress_fuzzer corpus/compress -artifact_prefix=./crashes_compress/
./fuzz/uncompress_fuzzer corpus/uncompress -artifact_prefix=./crashes_uncompress/
```

Good seed corpus for `uncompress_fuzzer`: small valid zlib streams (e.g. output of `compress` or `minigzip`). For `compress_fuzzer`, any small binary files are fine.

## Sanitizers

Targets are built with AddressSanitizer and UndefinedBehaviorSanitizer so that memory and undefined behavior bugs produce clear findings.
