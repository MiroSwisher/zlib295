# Security Analysis of zlib via Coverage-Guided Fuzzing

CS295 final project: libFuzzer-based fuzzing of zlib, CVE rediscovery, and ablation studies.

**This repository does not include the zlib library.** It contains our harnesses, scripts, and documentation. You clone zlib separately and overlay our changes.

---

## Repo layout

| Path | Description |
|------|-------------|
| **fuzz/** | libFuzzer harnesses and build logic for **upstream zlib** (copy into `zlib/fuzz/`) |
| **setup/** | Patch and script to enable fuzz in a vanilla zlib CMake build |
| **cve_harnesses/** | CVE-specific harnesses and build script for **zlib v1.2.11 / v1.2.12** |
| **ablation/** | Ablation study scripts, logs, and results |
| **CVE_REDISCOVERY.md** | CVE-2022-37434 and CVE-2018-25032 rediscovery report |
| **ablation/RESULTS_SUMMARY.md** | Ablation study summary |

---

## 1. Fuzzing latest zlib (e.g. v1.3.2)

### 1.1 Clone zlib

```bash
git clone https://github.com/madler/zlib.git
cd zlib
# optional: git checkout v1.3.2
```

### 1.2 Apply our fuzz overlay

From this repo’s root:

```bash
./setup/apply_setup.sh /path/to/zlib
```

This copies `fuzz/` into `zlib/fuzz/` and patches `zlib/CMakeLists.txt` to add `ZLIB_BUILD_FUZZ` and `add_subdirectory(fuzz)`.

If the patch fails (e.g. different zlib version), add the following by hand:

1. In `CMakeLists.txt`, after `option(ZLIB_BUILD_STATIC ...)` add:
   ```cmake
   option(ZLIB_BUILD_FUZZ "Enable libFuzzer fuzz targets (requires Clang)" OFF)
   ```
2. Before `add_subdirectory(contrib)`, add:
   ```cmake
   if(ZLIB_BUILD_FUZZ)
       add_subdirectory(fuzz)
   endif(ZLIB_BUILD_FUZZ)
   ```
3. Copy this repo’s `fuzz/` directory into `zlib/fuzz/`.

### 1.3 Build

**macOS (use Homebrew LLVM; Xcode Clang usually lacks libFuzzer):**

```bash
brew install llvm
cd /path/to/zlib
mkdir build && cd build
cmake .. -DZLIB_BUILD_FUZZ=ON -DCMAKE_C_COMPILER=$(brew --prefix llvm)/bin/clang
make
```

**Linux:**

```bash
cd /path/to/zlib && mkdir build && cd build
cmake .. -DZLIB_BUILD_FUZZ=ON -DCMAKE_C_COMPILER=clang
make
```

Fuzz binaries are in `build/fuzz/`. See `fuzz/README.md` for run options and seed corpus generation.

---

## 2. CVE rediscovery (zlib v1.2.11 and v1.2.12)

To reproduce CVE-2022-37434 and CVE-2018-25032 you need two separate zlib clones at **this repo’s root** named `zlib-1.2.12` and `zlib-1.2.11`:

```bash
# from this repo root
git clone https://github.com/madler/zlib.git zlib-1.2.12
git -C zlib-1.2.12 checkout v1.2.12

git clone https://github.com/madler/zlib.git zlib-1.2.11
git -C zlib-1.2.11 checkout v1.2.11
```

Then build and run the CVE harnesses:

```bash
bash cve_harnesses/build_and_run.sh
python3 cve_harnesses/gen_seeds.py   # generate seed corpora
# run fuzzers (see CVE_REDISCOVERY.md for full commands)
```

Details and ASan output are in **CVE_REDISCOVERY.md**.

---

## 3. Ablation study

With latest zlib built (and, for CVE experiments, `zlib-1.2.11` / `zlib-1.2.12` in place), you can rerun the ablation:

```bash
bash ablation/run_ablation.sh
python3 ablation/parse_results.py
```

See **ablation/RESULTS_SUMMARY.md** for interpretation.

---

## 4. What to commit

- Commit: `fuzz/`, `setup/`, `cve_harnesses/`, `ablation/` (scripts and `RESULTS_SUMMARY.md`; optionally exclude `ablation/logs/` and `ablation/results.csv` if large), `README.md`, `CVE_REDISCOVERY.md`, `proposal.txt`, `project_rubric.txt`, `.gitignore`.
- Do **not** commit: `zlib/`, `zlib-1.2.11/`, `zlib-1.2.12/`, `cve_builds/`, or other build/crash/corpus artifacts (they are in `.gitignore`).
