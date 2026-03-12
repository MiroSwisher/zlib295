import os
import matplotlib.pyplot as plt
import pandas as pd
from matplotlib.patches import Patch

BASE = os.path.dirname(__file__)
csv_path = os.path.join(BASE, "results.csv")
df = pd.read_csv(csv_path)

if "seaborn-v0_8-darkgrid" in plt.style.available:
    plt.style.use("seaborn-v0_8-darkgrid")
else:
    plt.style.use("seaborn-darkgrid")

# Color palette (color-blind friendly)
BLUE = "#4C78A8"
ORANGE = "#F58518"
GREEN = "#54A24B"
RED = "#E45756"

AB_META = {
    "A1_dict_noseed": ("A1", "Dict=Yes, Seeds=No", BLUE),
    "A2_nodict_noseed": ("A2", "Dict=No, Seeds=No", ORANGE),
    "B1_dict_seed": ("B1", "Dict=Yes, Seeds=Yes", GREEN),
    "B2_dict_noseed": ("B2", "Dict=Yes, Seeds=No", RED),
}


def save_ab_plot(metric_col: str, ylabel: str, title: str, out_name: str) -> None:
    ab = df[df["experiment"].str.startswith(("A", "B"))].copy()
    ab = ab[ab["experiment"].isin(AB_META.keys())]
    ab["short"] = ab["experiment"].map(lambda x: AB_META[x][0])
    ab["color"] = ab["experiment"].map(lambda x: AB_META[x][2])
    ab = ab.sort_values("short")

    labels = ab["short"].tolist()
    values = ab[metric_col].astype(float).tolist()
    colors = ab["color"].tolist()

    fig, ax = plt.subplots(figsize=(7.2, 4.2))
    bars = ax.bar(labels, values, color=colors, alpha=0.92)
    ax.set_ylabel(ylabel)
    ax.set_xlabel("Experiment")
    ax.set_title(title)

    ymax = max(values) if values else 1.0
    ax.set_ylim(0, ymax * 1.18)
    for bar, v in zip(bars, values):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            v + ymax * 0.025,
            f"{int(v)}",
            ha="center",
            va="bottom",
            fontsize=9,
        )

    legend_handles = [
        Patch(color=AB_META[k][2], label=f"{AB_META[k][0]}: {AB_META[k][1]}")
        for k in sorted(AB_META.keys(), key=lambda x: AB_META[x][0])
    ]
    ax.legend(
        handles=legend_handles,
        loc="upper center",
        bbox_to_anchor=(0.5, -0.18),
        ncol=2,
        frameon=False,
        fontsize=8.5,
    )

    plt.tight_layout()
    plt.savefig(os.path.join(BASE, out_name), dpi=170, bbox_inches="tight")
    plt.close(fig)


def save_c_plot() -> None:
    c = df[df["experiment"].str.startswith("C")].copy()
    c = c.sort_values("experiment")
    labels = ["C1", "C2", "C3", "C4"][: len(c)]
    heights = [1.0] * len(c)

    fig, ax = plt.subplots(figsize=(6.8, 3.8))
    bars = ax.bar(labels, heights, color=BLUE, alpha=0.92)
    ax.set_ylim(0, 1.35)
    ax.set_yticks([])
    ax.set_ylabel("Outcome")
    ax.set_xlabel("Experiment")
    ax.set_title("CVE-2022-37434: All Configurations Crash Quickly")

    for bar in bars:
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            1.03,
            "<1s crash",
            ha="center",
            va="bottom",
            fontsize=9,
            fontweight="semibold",
        )

    ax.legend(
        handles=[Patch(color=BLUE, label="Crash observed")],
        loc="upper center",
        bbox_to_anchor=(0.5, -0.15),
        frameon=False,
        fontsize=9,
    )

    plt.tight_layout()
    plt.savefig(os.path.join(BASE, "time_to_crash_C.png"), dpi=170, bbox_inches="tight")
    plt.close(fig)


def save_d_plot() -> None:
    d = df[df["experiment"].str.startswith("D")].copy()
    d = d.sort_values("experiment")

    short_labels = ["D1", "D2", "D3", "D4"][: len(d)]
    heights = [1.0] * len(d)
    crash_flags = d["crashed"].tolist()
    colors = [BLUE if flag == "YES" else RED for flag in crash_flags]
    annotations = ["<1s crash" if flag == "YES" else ">120s no crash" for flag in crash_flags]

    fig, ax = plt.subplots(figsize=(7.0, 4.0))
    bars = ax.bar(short_labels, heights, color=colors, alpha=0.92)
    ax.set_ylim(0, 1.35)
    ax.set_yticks([])
    ax.set_ylabel("Outcome")
    ax.set_xlabel("Experiment")
    ax.set_title("CVE-2018-25032: Seed Corpus is Required")

    for bar, txt in zip(bars, annotations):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            1.03,
            txt,
            ha="center",
            va="bottom",
            fontsize=9,
            fontweight="semibold",
        )

    legend_handles = [
        Patch(color=BLUE, label="Crash observed"),
        Patch(color=RED, label="No crash within 120s"),
    ]
    ax.legend(
        handles=legend_handles,
        loc="upper center",
        bbox_to_anchor=(0.5, -0.16),
        ncol=2,
        frameon=False,
        fontsize=9,
    )

    mapping = "D1: dict+seed   D2: no-dict+seed   D3: dict+no-seed   D4: no-dict+no-seed"
    fig.text(0.5, -0.03, mapping, ha="center", fontsize=8.5)

    plt.tight_layout()
    plt.savefig(os.path.join(BASE, "time_to_crash_D.png"), dpi=170, bbox_inches="tight")
    plt.close(fig)


save_ab_plot(
    metric_col="cov_60s",
    ylabel="Coverage at 60s (cov)",
    title="Coverage at 60s for Dictionary / Seed Ablations",
    out_name="cov_60s_AB.png",
)
save_ab_plot(
    metric_col="ft_60s",
    ylabel="Features at 60s (ft)",
    title="Features at 60s for Dictionary / Seed Ablations",
    out_name="ft_60s_AB.png",
)
save_c_plot()
save_d_plot()

print(
    "Wrote clean plots: cov_60s_AB.png, ft_60s_AB.png, "
    "time_to_crash_C.png, time_to_crash_D.png in",
    BASE,
)
