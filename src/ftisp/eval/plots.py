from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.colors import LinearSegmentedColormap  # noqa: E402

SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK_2 = "#52514e"
MUTED = "#898781"
GRID = "#e1e0d9"
AXIS = "#c3c2b7"

# Colour follows the aggregator everywhere (figures and dashboard), never its rank.
AGG_COLORS = {
    "fedavg": "#2a78d6",
    "median": "#eb6834",
    "trimmed_mean": "#1baf7a",
    "krum": "#eda100",
}
AGG_LABELS = {
    "fedavg": "FedAvg",
    "median": "Median",
    "trimmed_mean": "Trimmed mean",
    "krum": "Krum",
}
BLUE_RAMP = ["#cde2fb", "#9ec5f4", "#6da7ec", "#3987e5", "#256abf", "#184f95", "#0d366b"]


def _style(ax) -> None:
    ax.set_facecolor(SURFACE)
    ax.grid(axis="y", color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)
    ax.spines["bottom"].set_color(AXIS)
    ax.tick_params(colors=MUTED, labelsize=9, length=0)
    ax.xaxis.label.set_color(INK_2)
    ax.yaxis.label.set_color(INK_2)


def _figure(ncols: int = 1, width: float = 6.4, height: float = 3.8):
    fig, axes = plt.subplots(1, ncols, figsize=(width, height), facecolor=SURFACE, squeeze=False)
    for ax in axes[0]:
        _style(ax)
    return fig, axes[0]


def _line(ax, x, y, color) -> None:
    ax.plot(x, y, color=color, linewidth=2, solid_capstyle="round", solid_joinstyle="round")
    ax.plot(x[-1], y[-1], "o", color=color, markersize=8, markeredgecolor=SURFACE,
            markeredgewidth=2, zorder=3, clip_on=False)


def _end_labels(ax, ends: list[tuple[float, str]], y_range: float) -> None:
    # Direct-label line ends only when they are far enough apart; otherwise the legend carries it.
    values = sorted(v for v, _ in ends)
    if any(b - a < 0.07 * y_range for a, b in zip(values, values[1:])):
        return
    for value, text in ends:
        ax.annotate(text, xy=(1, value), xycoords=("axes fraction", "data"), xytext=(8, 0),
                    textcoords="offset points", va="center", fontsize=9, color=INK_2)


def _pct_axis(ax) -> None:
    ax.set_ylim(-0.02, 1.02)
    ax.set_yticks([0, 0.25, 0.5, 0.75, 1.0])
    ax.set_yticklabels(["0%", "25%", "50%", "75%", "100%"])


def _save(fig, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=200, bbox_inches="tight", facecolor=SURFACE)
    plt.close(fig)


def plot_attack_timeline(runs: dict[str, dict], clean: dict, path: Path) -> None:
    """Detection rate and accuracy per round, one line per aggregator, under the same attack."""
    start = next(iter(runs.values()))["config"]["attack_start_round"]
    fig, axes = _figure(ncols=3, width=15.5, height=4.2)
    panels = [
        ("detection_rate", "Attacks detected"),
        ("false_alarm_rate", "False alarms on normal traffic"),
        ("accuracy", "Overall accuracy (10 classes)"),
    ]
    for ax, (metric, title) in zip(axes, panels):
        rounds = [r["round"] for r in clean["history"]]
        ax.plot(rounds, [r[metric] for r in clean["history"]], color=AXIS, linewidth=2)
        ends = []
        for agg, res in runs.items():
            ys = [r[metric] for r in res["history"]]
            _line(ax, [r["round"] for r in res["history"]], ys, AGG_COLORS[agg])
            ends.append((ys[-1], f"{AGG_LABELS[agg]} {ys[-1]:.0%}"))
        ax.axvline(start - 0.5, color=MUTED, linewidth=1)
        ax.annotate("poisoning starts", xy=(start - 0.5, 0.0), xytext=(-5, 2),
                    textcoords="offset points", ha="right", fontsize=8, color=MUTED)
        _pct_axis(ax)
        ax.set_xlim(1, rounds[-1])
        ax.set_xlabel("Round")
        ax.set_title(title, loc="left", fontsize=11, color=INK, pad=10)
        _end_labels(ax, ends, 1.0)

    handles = [plt.Line2D([], [], color=AXIS, linewidth=2)]
    labels = ["No attack (FedAvg)"]
    for agg in runs:
        handles.append(plt.Line2D([], [], color=AGG_COLORS[agg], linewidth=2))
        labels.append(AGG_LABELS[agg])
    fig.legend(handles, labels, loc="upper center", ncol=len(labels), frameon=False,
               fontsize=9, labelcolor=INK_2, bbox_to_anchor=(0.5, 1.06))
    fig.tight_layout(w_pad=7)
    _save(fig, path)


def plot_fraction_sweep(sweep: dict[str, list[tuple[float, float]]], assumed_f: int,
                        n_clients: int, path: Path) -> None:
    """Attacks detected (mean of the last rounds) as the share of malicious clients grows."""
    fig, (ax,) = _figure(width=7.4, height=4.2)
    ends = []
    for agg, points in sweep.items():
        xs = [p[0] for p in points]
        ys = [p[1] for p in points]
        _line(ax, xs, ys, AGG_COLORS[agg])
        ax.plot(xs[:-1], ys[:-1], "o", color=AGG_COLORS[agg], markersize=8,
                markeredgecolor=SURFACE, markeredgewidth=2, zorder=3, clip_on=False)
        ends.append((ys[-1], f"{AGG_LABELS[agg]} {ys[-1]:.0%}"))
    ax.axvline(assumed_f, color=MUTED, linewidth=1)
    ax.annotate(f"Krum's assumption:\nat most {assumed_f} of {n_clients} attackers",
                xy=(assumed_f, 0.5), xytext=(9, 0), textcoords="offset points",
                ha="left", va="center", fontsize=8, color=MUTED)
    _pct_axis(ax)
    xs = [p[0] for p in next(iter(sweep.values()))]
    ax.set_xticks(xs)
    ax.set_xticklabels([f"{x:.0%}" for x in xs])
    ax.set_xlabel("Share of organizations that are malicious")
    ax.set_title("Attacks detected vs. number of attackers", loc="left", fontsize=11,
                 color=INK, pad=10)
    _end_labels(ax, ends, 1.0)
    ax.legend([plt.Line2D([], [], color=AGG_COLORS[a], linewidth=2) for a in sweep],
              [AGG_LABELS[a] for a in sweep], frameon=False, fontsize=9, labelcolor=INK_2,
              loc="lower left")
    _save(fig, path)


def plot_partition(result: dict, path: Path) -> None:
    """Share of each organization's data that falls in each class (rows sum to 100%)."""
    counts = result["client_class_counts"]
    shares = [[c / max(sum(row), 1) for c in row] for row in counts]
    malicious = set(result["malicious"])
    fig, (ax,) = _figure(width=8.6, height=4.6)
    ax.grid(False)
    ax.spines["bottom"].set_visible(False)
    cmap = LinearSegmentedColormap.from_list("blue", BLUE_RAMP)
    im = ax.imshow(shares, cmap=cmap, vmin=0, vmax=1, aspect="auto")
    ax.set_xticks(range(len(result["classes"])))
    ax.set_xticklabels(result["classes"], rotation=35, ha="right")
    ax.set_yticks(range(len(counts)))
    ax.set_yticklabels(
        [f"Org {i + 1}{'  (malicious)' if i in malicious else ''}  ·  {sum(row):,}"
         for i, row in enumerate(counts)]
    )
    ax.tick_params(colors=INK_2)
    ax.set_title("What each organization sees (non-IID, Dirichlet α = "
                 f"{result['config']['alpha']})", loc="left", fontsize=11, color=INK, pad=10)
    bar = fig.colorbar(im, ax=ax, fraction=0.03, pad=0.02)
    bar.outline.set_visible(False)
    bar.ax.tick_params(colors=MUTED, labelsize=8, length=0)
    bar.set_ticks([0, 0.5, 1])
    bar.set_ticklabels(["0%", "50%", "100%"])
    bar.set_label("share of the organization's flows", color=INK_2, fontsize=8)
    _save(fig, path)
