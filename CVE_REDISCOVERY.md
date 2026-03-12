# CVE Rediscovery Results — zlib Fuzzing Project

## Overview

We used **libFuzzer** with **AddressSanitizer (ASan)** to rediscover two known
CVEs in older versions of zlib. Both were detected within seconds of starting
the fuzzer with properly crafted harnesses and seed corpora.

---

## CVE-2022-37434 — Heap Buffer Overflow in `inflate()`

| Field             | Value                                              |
|-------------------|----------------------------------------------------|
| **CVE ID**        | CVE-2022-37434                                     |
| **CVSS Score**    | 9.8 (Critical)                                     |
| **Affected**      | zlib ≤ 1.2.12                                      |
| **Fixed in**      | zlib 1.2.13                                        |
| **Bug class**     | Heap-based buffer overflow / over-read              |
| **Location**      | `inflate.c:769`, `inflate()` → `zmemcpy()`         |
| **Trigger**       | `inflateGetHeader()` + gzip stream with large FEXTRA field |

### Root Cause

When an application calls `inflateGetHeader()` before `inflate()`, the inflate
state stores a pointer to a user-provided buffer (`head->extra`) and a maximum
size (`head->extra_max`). If the gzip stream's extra field (`XLEN`) exceeds
`extra_max`, and inflate processes the extra data across **multiple calls** (i.e.,
the extra data arrives in chunks), the variable `len` grows past `extra_max`.
The expression `extra_max - len` then wraps around (unsigned underflow),
causing `zmemcpy` to attempt a ~4 GB read from a small heap buffer.

### Vulnerable Code (inflate.c:768–771)

```c
len = state->head->extra_len - state->length;
zmemcpy(state->head->extra + len, next,
        len + copy > state->head->extra_max ?
        state->head->extra_max - len : copy);
```

### Harness Design

Key insight: the harness must **feed data in small chunks** (not all at once)
so the EXTRA state is re-entered across multiple `inflate()` calls. The first
two bytes of the fuzz input control `extra_buf_size` and `chunk_size`. The
remaining bytes are a (potentially fuzz-mutated) gzip stream.

- Source: `cve_harnesses/cve_2022_37434_fuzzer.c`
- Seed generator: `cve_harnesses/gen_seeds.py` (creates gzip streams with
  varying FEXTRA sizes and buffer configurations)

### ASan Report

```
==82014==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x608000000afb
  at pc 0x000102794570 bp 0x00016dcbcc90 sp 0x00016dcbc440
READ of size 4294967295 at 0x608000000afb thread T0
    #0 __asan_memcpy
    #1 inflate inflate.c:769
    #2 LLVMFuzzerTestOneInput cve_2022_37434_fuzzer.c:76

0x608000000afb is located 0 bytes after 91-byte region [0x608000000aa0,0x608000000afb)
SUMMARY: AddressSanitizer: heap-buffer-overflow inflate.c:769 in inflate
```

### Result

- **Time to crash**: ~2 seconds from fuzzer start
- **Crashing input**: 91 bytes (already minimal)
- **Artifact**: `cve_builds/cve-2022-37434/crashes/crash-239b1a5b44d46266c16dfc4341d72c1a31d37082`

---

## CVE-2018-25032 — Global Buffer Overflow in `deflate()`

| Field             | Value                                              |
|-------------------|----------------------------------------------------|
| **CVE ID**        | CVE-2018-25032                                     |
| **CVSS Score**    | 7.5 (High)                                         |
| **Affected**      | zlib ≤ 1.2.11                                      |
| **Fixed in**      | zlib 1.2.12                                        |
| **Bug class**     | Global buffer overflow (OOB read)                   |
| **Location**      | `trees.c:1091`, `compress_block()` → `_dist_code`  |
| **Trigger**       | `deflateInit2()` with Z_FIXED strategy + input with many distant matches |

### Root Cause

When compressing with `Z_FIXED` strategy (fixed Huffman codes), inputs that
generate many distant matches cause the pending buffer to grow beyond its
allocated region. Since the pending buffer overlays the distance symbol table
(`_dist_code`), the overflow corrupts the table, leading to out-of-bounds reads
from `_dist_code` in `compress_block()`.

The bug is exacerbated by low `memLevel` values (e.g., `memLevel=1`), which
create smaller internal buffers that overflow more easily.

### Harness Design

The harness uses `deflateInit2()` with `Z_FIXED` strategy and fuzz-driven
`level`, `windowBits`, and `memLevel` (crucial — the original harness with
`memLevel=8` did not trigger the bug). It then performs a round-trip
(deflate + inflate) with assertion checks.

- Source: `cve_harnesses/cve_2018_25032_fuzzer.c`
- Seed: Known trigger file from zlib-ng project (`test/CVE-2018-25032/fixed.txt`)

### ASan Report

```
==82498==ERROR: AddressSanitizer: global-buffer-overflow on address 0x0001005e7845
  at pc 0x0001005a66a8 bp 0x00016f885cb0 sp 0x00016f885ca8
READ of size 1 at 0x0001005e7845 thread T0
    #0 compress_block trees.c:1091
    #1 _tr_flush_block trees.c:979
    #2 deflate_slow deflate.c:2011
    #3 deflate deflate.c:1003
    #4 LLVMFuzzerTestOneInput cve_2018_25032_fuzzer.c:53

0x0001005e7845 is located 5 bytes after global variable '_dist_code'
  defined in 'trees.c' (0x0001005e7640) of size 512
SUMMARY: AddressSanitizer: global-buffer-overflow trees.c:1091 in compress_block
```

### Result

- **Time to crash**: ~2 seconds from fuzzer start (using PoC seed)
- **Original crashing input**: 32,771 bytes
- **Minimized crashing input**: 21,204 bytes
- **Artifact**: `cve_builds/cve-2018-25032/crashes/minimized-from-5cb542c6881335b195181ed97d3396de827d0218`

---

## Build and Reproduction Instructions

### Prerequisites

- macOS with Homebrew LLVM: `brew install llvm`
- Source repos: `zlib-1.2.12/` (v1.2.12 tag) and `zlib-1.2.11/` (v1.2.11 tag)

### Build

```bash
# Build both CVE harnesses
bash cve_harnesses/build_and_run.sh
```

### Reproduce CVE-2022-37434

```bash
./cve_builds/cve-2022-37434/cve_2022_37434_fuzzer \
    cve_builds/cve-2022-37434/corpus \
    -dict=zlib/fuzz/zlib.dict \
    -artifact_prefix=cve_builds/cve-2022-37434/crashes/ \
    -max_len=2048
```

### Reproduce CVE-2018-25032

```bash
./cve_builds/cve-2018-25032/cve_2018_25032_fuzzer \
    cve_builds/cve-2018-25032/corpus \
    -dict=zlib/fuzz/zlib.dict \
    -artifact_prefix=cve_builds/cve-2018-25032/crashes/ \
    -max_len=65536
```

---

## Project Directory Structure

```
final_project/
├── zlib/                   # Latest zlib (v1.3.2) with integrated fuzz harnesses
│   └── fuzz/               # General-purpose inflate/deflate fuzz harnesses
├── zlib-1.2.12/            # Vulnerable zlib for CVE-2022-37434
├── zlib-1.2.11/            # Vulnerable zlib for CVE-2018-25032
├── cve_harnesses/          # CVE-specific harnesses and build scripts
│   ├── cve_2022_37434_fuzzer.c
│   ├── cve_2018_25032_fuzzer.c
│   ├── build_and_run.sh
│   ├── gen_seeds.py
│   └── test_cve2018_v2.c   # Standalone reproducer
├── cve_builds/             # Build outputs and crash artifacts
│   ├── cve-2022-37434/
│   │   ├── corpus/         # Seed corpus (gzip with FEXTRA fields)
│   │   └── crashes/        # Crash artifacts
│   └── cve-2018-25032/
│       ├── corpus/         # Seed corpus (distant-match patterns)
│       └── crashes/        # Crash + minimized artifacts
└── CVE_REDISCOVERY.md      # This document
```

## Key Lessons Learned

1. **Harness design is critical**: CVE-2022-37434 required feeding data in
   small chunks, not all at once. A naive harness that provides the full input
   to `inflate()` in one call cannot trigger the multi-chunk EXTRA overflow.

2. **Parameter space matters**: CVE-2018-25032 only triggers with specific
   `memLevel` values. A harness that hardcodes `memLevel=8` (the default)
   will never find the bug. Fuzzing the configuration parameters alongside
   the data is essential.

3. **Seed corpus quality determines time-to-bug**: Both CVEs were found within
   seconds when provided with appropriate seed corpora (well-formed gzip
   streams for CVE-2022-37434, distant-match patterns for CVE-2018-25032).
   Without seeds, the fuzzers spent millions of iterations at very low
   coverage.

4. **ASan is essential**: CVE-2018-25032 manifests as a 1-byte OOB read from a
   global buffer. Without ASan, this would silently corrupt data but rarely
   crash, making it nearly impossible to detect via fuzzing alone.
