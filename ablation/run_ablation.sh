#!/bin/bash
set -e

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ABLATION_DIR="$PROJECT_DIR/ablation"
LOGS_DIR="$ABLATION_DIR/logs"
DICT="$PROJECT_DIR/zlib/fuzz/zlib.dict"

INFLATE_FUZZER="$PROJECT_DIR/zlib/build/fuzz/inflate_fuzzer"
SEED_CORPUS_INFLATE="$PROJECT_DIR/zlib/build/corpus/inflate_with_header"

CVE37434_FUZZER="$PROJECT_DIR/cve_builds/cve-2022-37434/cve_2022_37434_fuzzer"
CVE37434_SEEDS="$PROJECT_DIR/cve_builds/cve-2022-37434/corpus"

CVE25032_FUZZER="$PROJECT_DIR/cve_builds/cve-2018-25032/cve_2018_25032_fuzzer"
CVE25032_SEEDS="$PROJECT_DIR/cve_builds/cve-2018-25032/corpus"

rm -rf "$LOGS_DIR"
mkdir -p "$LOGS_DIR"

run_with_timeout() {
  local timeout_s="$1"
  shift
  "$@" &
  local pid=$!
  (sleep "$timeout_s" && kill "$pid" 2>/dev/null) &
  local watchdog=$!
  wait "$pid" 2>/dev/null || true
  kill "$watchdog" 2>/dev/null || true
  wait "$watchdog" 2>/dev/null || true
}

run_experiment() {
  local name="$1"
  local fuzzer="$2"
  local duration="$3"
  local use_dict="$4"
  local seed_dir="$5"
  local max_len="${6:-2048}"
  local hard_timeout=$(( duration + 15 ))

  local tmp_corpus
  tmp_corpus=$(mktemp -d)

  if [ -n "$seed_dir" ] && [ -d "$seed_dir" ]; then
    cp "$seed_dir"/* "$tmp_corpus/" 2>/dev/null || true
  fi

  local log_file="$LOGS_DIR/${name}.log"

  local args=("$tmp_corpus" "-max_total_time=$duration" "-max_len=$max_len" "-print_final_stats=1")
  if [ "$use_dict" = "yes" ]; then
    args+=("-dict=$DICT")
  fi

  echo "[$(date +%H:%M:%S)] Running $name (${duration}s)..."
  run_with_timeout "$hard_timeout" "$fuzzer" "${args[@]}" >"$log_file" 2>&1
  echo "[$(date +%H:%M:%S)] Done: $name -> $log_file"

  rm -rf "$tmp_corpus"
}

echo "============================================"
echo "  Ablation Study — zlib Fuzzing Project"
echo "  Started: $(date)"
echo "============================================"

echo ""
echo "--- Experiment 1: Dictionary Impact ---"
run_experiment "A1_dict_noseed"   "$INFLATE_FUZZER" 60 "yes" ""
run_experiment "A2_nodict_noseed" "$INFLATE_FUZZER" 60 "no"  ""

echo ""
echo "--- Experiment 2: Seed Corpus Impact ---"
run_experiment "B1_dict_seed"   "$INFLATE_FUZZER" 60 "yes" "$SEED_CORPUS_INFLATE"
run_experiment "B2_dict_noseed" "$INFLATE_FUZZER" 60 "yes" ""

echo ""
echo "--- Experiment 3a: CVE-2022-37434 Time-to-Bug ---"
run_experiment "C1_cve37434_dict_seed"     "$CVE37434_FUZZER" 120 "yes" "$CVE37434_SEEDS" 2048
run_experiment "C2_cve37434_nodict_seed"   "$CVE37434_FUZZER" 120 "no"  "$CVE37434_SEEDS" 2048
run_experiment "C3_cve37434_dict_noseed"   "$CVE37434_FUZZER" 120 "yes" ""                2048
run_experiment "C4_cve37434_nodict_noseed" "$CVE37434_FUZZER" 120 "no"  ""                2048

echo ""
echo "--- Experiment 3b: CVE-2018-25032 Time-to-Bug ---"
run_experiment "D1_cve25032_dict_seed"     "$CVE25032_FUZZER" 120 "yes" "$CVE25032_SEEDS" 65536
run_experiment "D2_cve25032_nodict_seed"   "$CVE25032_FUZZER" 120 "no"  "$CVE25032_SEEDS" 65536
run_experiment "D3_cve25032_dict_noseed"   "$CVE25032_FUZZER" 120 "yes" ""                65536
run_experiment "D4_cve25032_nodict_noseed" "$CVE25032_FUZZER" 120 "no"  ""                65536

echo ""
echo "============================================"
echo "  All experiments complete! $(date)"
echo "  Logs in: $LOGS_DIR/"
echo "============================================"
