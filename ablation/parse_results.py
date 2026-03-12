#!/usr/bin/env python3
"""Parse libFuzzer log files from ablation experiments into a CSV summary."""
import csv
import os
import re
import sys

LOGS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
OUTPUT_CSV = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results.csv")


def parse_coverage_log(path):
    """Extract coverage timeline and final stats from a libFuzzer log."""
    entries = []
    final_cov = 0
    final_ft = 0
    final_execs = 0
    crashed = False
    crash_time_s = None

    with open(path, "r", errors="replace") as f:
        for line in f:
            # Detect ASan crash
            if "ERROR: AddressSanitizer:" in line:
                crashed = True

            # INITED or pulse/NEW/REDUCE lines with cov/ft
            m = re.search(
                r"#(\d+)\s+\S+\s+cov:\s+(\d+)\s+ft:\s+(\d+).*exec/s:\s+(\d+)",
                line,
            )
            if m:
                execs = int(m.group(1))
                cov = int(m.group(2))
                ft = int(m.group(3))
                exec_s = int(m.group(4))
                elapsed_s = execs / exec_s if exec_s > 0 else 0
                entries.append(
                    {"execs": execs, "cov": cov, "ft": ft, "elapsed_s": elapsed_s}
                )
                final_cov = max(final_cov, cov)
                final_ft = max(final_ft, ft)
                final_execs = max(final_execs, execs)

            # INITED line (exec/s may be 0)
            m2 = re.search(r"#(\d+)\s+INITED\s+cov:\s+(\d+)\s+ft:\s+(\d+)", line)
            if m2:
                cov = int(m2.group(2))
                ft = int(m2.group(3))
                entries.append({"execs": 0, "cov": cov, "ft": ft, "elapsed_s": 0})
                final_cov = max(final_cov, cov)
                final_ft = max(final_ft, ft)

            # elapsed_ms from crash artifact footer or stat_number_of_executed_units
            m3 = re.search(r"stat_number_of_executed_units:\s+(\d+)", line)
            if m3:
                final_execs = int(m3.group(1))

    # Estimate crash time from the last entry before crash
    if crashed and entries:
        crash_time_s = entries[-1]["elapsed_s"]

    return {
        "entries": entries,
        "final_cov": final_cov,
        "final_ft": final_ft,
        "final_execs": final_execs,
        "crashed": crashed,
        "crash_time_s": crash_time_s,
    }


def cov_at_time(entries, target_s):
    """Find coverage at the closest timestamp <= target_s."""
    best_cov = 0
    best_ft = 0
    for e in entries:
        if e["elapsed_s"] <= target_s:
            best_cov = max(best_cov, e["cov"])
            best_ft = max(best_ft, e["ft"])
        else:
            break
    return best_cov, best_ft


def main():
    if not os.path.isdir(LOGS_DIR):
        print(f"No logs directory found at {LOGS_DIR}")
        sys.exit(1)

    log_files = sorted(
        f for f in os.listdir(LOGS_DIR) if f.endswith(".log")
    )

    if not log_files:
        print("No log files found.")
        sys.exit(1)

    rows = []
    for fname in log_files:
        path = os.path.join(LOGS_DIR, fname)
        result = parse_coverage_log(path)
        name = fname.replace(".log", "")

        cov_10, ft_10 = cov_at_time(result["entries"], 10)
        cov_30, ft_30 = cov_at_time(result["entries"], 30)
        cov_60, ft_60 = cov_at_time(result["entries"], 60)

        rows.append({
            "experiment": name,
            "crashed": "YES" if result["crashed"] else "no",
            "crash_time_s": f"{result['crash_time_s']:.1f}" if result["crash_time_s"] is not None else "N/A",
            "final_cov": result["final_cov"],
            "final_ft": result["final_ft"],
            "total_execs": result["final_execs"],
            "cov_10s": cov_10,
            "ft_10s": ft_10,
            "cov_30s": cov_30,
            "ft_30s": ft_30,
            "cov_60s": cov_60,
            "ft_60s": ft_60,
        })

    fieldnames = [
        "experiment", "crashed", "crash_time_s",
        "final_cov", "final_ft", "total_execs",
        "cov_10s", "ft_10s", "cov_30s", "ft_30s", "cov_60s", "ft_60s",
    ]

    with open(OUTPUT_CSV, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Results written to {OUTPUT_CSV}")
    print()

    # Print a human-readable table
    header = f"{'Experiment':<35} {'Crash?':<6} {'Crash(s)':<9} {'Cov@10s':<8} {'Cov@30s':<8} {'Cov@60s':<8} {'FinalCov':<9} {'FinalFt':<9} {'Execs':<10}"
    print(header)
    print("-" * len(header))
    for r in rows:
        print(
            f"{r['experiment']:<35} {r['crashed']:<6} {r['crash_time_s']:<9} "
            f"{r['cov_10s']:<8} {r['cov_30s']:<8} {r['cov_60s']:<8} "
            f"{r['final_cov']:<9} {r['final_ft']:<9} {r['total_execs']:<10}"
        )


if __name__ == "__main__":
    main()
