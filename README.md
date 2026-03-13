# Security Analysis of zlib via Coverage-Guided Fuzzing

CS295 final project: libFuzzer-based fuzzing of zlib, CVE rediscovery, and ablation studies.

**This repository does not include the zlib library.** It contains our harnesses, scripts, and documentation. You clone zlib separately and overlay our changes.

---

## What we did

**Goal:** Show that coverage-guided fuzzing (libFuzzer) on zlib is effective by (1) integrating harnesses into the library build, (2) rediscovering two known CVEs in older versions, and (3) running ablation studies to quantify the impact of dictionary and seed corpus.

**What’s in this repo:**

- **fuzz/** — Four libFuzzer harnesses for **latest zlib** (inflate, deflate round-trip, compress, uncompress), plus CMake integration, dictionary, and seed corpus generator. Copy into a vanilla zlib tree and build with `ZLIB_BUILD_FUZZ=ON`.
- **cve_harnesses/** — Two **CVE-specific** harnesses and a build script that compile **vulnerable zlib v1.2.11 and v1.2.12** and run the fuzzers. Used to demonstrate that our methodology finds known bugs (CVE-2022-37434, CVE-2018-25032).
- **ablation/** — Scripts to run controlled experiments (dictionary on/off, seeds on/off) and parse coverage/time-to-crash from logs. Includes a results summary and figures (e.g. `cov_60s_AB.png`, `time_to_crash_C.png`, `time_to_crash_D.png`).
- **setup/** — Patch and script to add the fuzz targets to upstream zlib’s CMake without vendoring zlib.

**What we ran and found:**

- We built and fuzzed **latest zlib** (v1.3.2) with the four harnesses; no new bugs (expected for a mature library). We then checked out **zlib v1.2.12 and v1.2.11**, built them with our CVE harnesses, and **rediscovered CVE-2022-37434** (heap overflow in inflate with `inflateGetHeader` + large gzip extra field) and **CVE-2018-25032** (OOB in deflate with Z_FIXED). Both crash within seconds with the right seeds. We ran **ablation experiments** (dict vs no dict, seeds vs no seeds) and found that the **seed corpus is the decisive factor** for finding CVE-2018-25032; the dictionary has a more nuanced effect on coverage.

**Where to read more:**

- **CVE_REDISCOVERY.md** — CVE details, harness design, ASan snippets, and repro steps.
- **ablation/RESULTS_SUMMARY.md** — Ablation tables and interpretation.
- **proposal.txt** — Original project proposal and strategy.

---

## Repo layout

| Path                            | Description                                                                        |
| ------------------------------- | ---------------------------------------------------------------------------------- |
| **fuzz/**                       | libFuzzer harnesses and build logic for **upstream zlib** (copy into `zlib/fuzz/`) |
| **setup/**                      | Patch and script to enable fuzz in a vanilla zlib CMake build                      |
| **cve_harnesses/**              | CVE-specific harnesses and build script for **zlib v1.2.11 / v1.2.12**             |
| **ablation/**                   | Ablation study scripts, logs, and results                                          |
| **CVE_REDISCOVERY.md**          | CVE-2022-37434 and CVE-2018-25032 rediscovery report                               |
| **ablation/RESULTS_SUMMARY.md** | Ablation study summary                                                             |

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
