#!/usr/bin/env python3
"""
Generate the vulnerability / detection-efficiency figure set for the
bridge-bytecode obfuscation study.

Units of comparison are the five bridge protocols (Axelar, Wormhole, LayerZero,
Hyperlane, CCIP) rather than the batches B01..B05 used in the source-code phase
of this project.

Figures produced in ./ (alongside this script):

  01_overall_efficiency_all_protocols.png   detection efficiency per tool x protocol (original)
  02_per_vuln_orig_<PROTOCOL>.png     (x5)  per-vulnerability detection, original bytecode
  03_per_vuln_obf_<PROTOCOL>.png      (x5)  per-vulnerability detection, obfuscated bytecode
  04_tool_trend_orig_vs_obf.png             slope of efficiency, original -> obfuscated
  05_heatmap_orig_avg.png                   tool x vulnerability, mean over protocols (original)
  06_heatmap_obf_avg.png                    tool x vulnerability, mean over protocols (obfuscated)
  07_radar_orig_per_protocol.png            vulnerability profile per protocol (original)
  08_nv_positives_stacked.png               novel (new-after-obfuscation) positives, by tool
  09_efficiency_drop_heatmap.png            efficiency drop in points, tool x protocol
  10_tool_robustness_bar.png                persistence % per tool under obfuscation

Source data: smartbug/{original,obfuscated}/<protocol>/*.csv  (raw per-tool
exports from the SmartBugs runs). The raw exports are used in preference to the
pre-aggregated Analysis/*.xlsx workbooks because the workbooks record only one
tool per (contract, vulnerability) cell, which loses co-detections.
"""

from __future__ import annotations

import os
import re
import warnings
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.colors import LinearSegmentedColormap, TwoSlopeNorm
from matplotlib.patches import Patch

warnings.filterwarnings("ignore")

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
SMARTBUG = os.path.join(ROOT, "smartbug")
OUT = HERE

PROTOCOLS = ["Axelar", "Wormhole", "LayerZero", "Hyperlane", "CCIP"]
TOOLS = ["MAIAN", "Mythril", "Oyente", "Securify"]

VULNS = [
    "Reentrancy", "Integer", "Access_Control", "Delegatecall", "Unchecked_Call",
    "Timestamp", "TOD", "DoS", "Selfdestruct", "Locked_Ether", "Ether_Leak",
]
VULN_LABELS = {
    "Reentrancy": "Reentrancy", "Integer": "Integer", "Access_Control": "Access\ncontrol",
    "Delegatecall": "Delegate\ncall", "Unchecked_Call": "Unchecked\ncall",
    "Timestamp": "Timestamp", "TOD": "TOD", "DoS": "DoS",
    "Selfdestruct": "Self\ndestruct", "Locked_Ether": "Locked\nether",
    "Ether_Leak": "Ether\nleak",
}

# Securify's obfuscated exports carry a `patterns` column that repeats all eight
# pattern names on every row with violations == warnings == 0. That is the list
# of patterns *checked*, not patterns *violated*; counting it as findings would
# credit Securify with eight detections on every obfuscated contract. Flip this
# to True to reproduce the older Analysis/*.xlsx behaviour.
SECURIFY_PATTERNS_AS_FINDINGS = False

# --------------------------------------------------------------------------
# Palette (light mode, validated: adjacent-pair CVD dE 9.1, normal-vision 22.9)
# --------------------------------------------------------------------------

SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK_2 = "#52514e"
MUTED = "#898781"
GRID = "#e1e0d9"
AXIS = "#c3c2b7"

TOOL_COLOR = {
    "MAIAN": "#2a78d6",    # blue
    "Mythril": "#eb6834",  # orange
    "Oyente": "#1baf7a",   # aqua
    "Securify": "#eda100", # yellow
}
ACCENT = "#2a78d6"

# the lightest step stays a shade off the surface so a genuine zero still reads
# as a cell rather than dissolving into the background
SEQ_BLUE = LinearSegmentedColormap.from_list(
    "seq_blue",
    ["#eaf1f9", "#cde2fb", "#9ec5f4", "#6da7ec", "#3987e5", "#256abf", "#184f95", "#0d366b"],
)
ND_FILL = "#e6e5e0"
DIV_BR = LinearSegmentedColormap.from_list(
    "div_blue_red",
    ["#0d366b", "#256abf", "#6da7ec", "#cde2fb", "#f0efec", "#f6c9c9", "#e88b8b", "#d03b3b", "#8f1f1f"],
)

plt.rcParams.update({
    "figure.facecolor": SURFACE,
    "axes.facecolor": SURFACE,
    "savefig.facecolor": SURFACE,
    "font.family": "sans-serif",
    "font.sans-serif": ["DejaVu Sans"],
    "text.color": INK,
    "axes.labelcolor": INK_2,
    "axes.edgecolor": AXIS,
    "xtick.color": MUTED,
    "ytick.color": MUTED,
    "axes.titlesize": 12,
    "axes.labelsize": 9.5,
    "xtick.labelsize": 9,
    "ytick.labelsize": 9,
    "legend.fontsize": 9,
    "figure.dpi": 150,
    "savefig.dpi": 200,
    "savefig.bbox": "tight",
})


def style_axes(ax, ygrid=True, xgrid=False):
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(AXIS)
        ax.spines[side].set_linewidth(0.8)
    ax.set_axisbelow(True)
    ax.grid(ygrid, axis="y", color=GRID, linewidth=0.8)
    ax.grid(xgrid, axis="x", color=GRID, linewidth=0.8)
    ax.tick_params(length=0)


def figtitle(fig, title, subtitle=None, y=0.99):
    fig.text(0.008, y, title, ha="left", va="top", fontsize=14.5, fontweight="bold", color=INK)
    if subtitle:
        fig.text(0.008, y - 0.045, subtitle, ha="left", va="top", fontsize=9.5, color=INK_2)


def footnote(fig, text, y=0.005):
    fig.text(0.008, y, text, ha="left", va="bottom", fontsize=7.6, color=MUTED)


# --------------------------------------------------------------------------
# Vulnerability-category mappings
# --------------------------------------------------------------------------

MAIAN_MAP = {"Prodigal": "Ether_Leak", "Suicidal": "Selfdestruct", "Locking": "Locked_Ether"}

MYTHRIL_MAP = {
    "integer arithmetic bugs": "Integer",
    "dependence on predictable environment variable": "Timestamp",
    "external call to user-supplied address": "Unchecked_Call",
    "multiple calls in a single transaction": "DoS",
    "transaction order dependence": "TOD",
    "requirement violation": "DoS",
    "exception state": "DoS",
    "unprotected selfdestruct": "Selfdestruct",
    "delegatecall to user-supplied address": "Delegatecall",
    "unprotected ether withdrawal": "Ether_Leak",
    "state access after external call": "Reentrancy",
}

OYENTE_MAP = {
    "callstack depth attack": "Unchecked_Call",
    "callstackdepthattack": "Unchecked_Call",
    "callstack_depth_attack": "Unchecked_Call",
    "transaction ordering dependence": "TOD",
    "transactionorderingdependence": "TOD",
    "transaction_ordering_dependence": "TOD",
    "timestamp dependency": "Timestamp",
    "timestampdependency": "Timestamp",
    "timestamp_dependency": "Timestamp",
    "reentrancy": "Reentrancy",
    "re-entrancy": "Reentrancy",
    "reentrancy_bug": "Reentrancy",
    "integer overflow": "Integer",
    "integer underflow": "Integer",
    "parity multisig bug 2": "Access_Control",
}

SECURIFY_MAP = {
    "dao": "Reentrancy",
    "daoconstantgas": "Reentrancy",
    "missinginputvalidation": "Access_Control",
    "todamount": "TOD",
    "todreceiver": "TOD",
    "todtransfer": "TOD",
    "unhandledexception": "Unchecked_Call",
    "unrestrictedetherflow": "Ether_Leak",
    "unrestrictedwrite": "Access_Control",
    "lockedether": "Locked_Ether",
}


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(s).lower())


def _truthy(v) -> bool:
    if isinstance(v, (bool, np.bool_)):
        return bool(v)
    if pd.isna(v):
        return False
    s = str(v).strip().lower()
    return s in {"yes", "true", "1", "y"}


def _col(df: pd.DataFrame, *names):
    """Case-insensitive column lookup."""
    lut = {_norm(c): c for c in df.columns}
    for n in names:
        if _norm(n) in lut:
            return lut[_norm(n)]
    return None


# --------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------

def _path(version: str, protocol: str, kind: str) -> str | None:
    p = protocol.lower()
    prefix = "" if version == "original" else "obs_"
    f = os.path.join(SMARTBUG, version, p, f"{prefix}{p}_{kind}.csv")
    return f if os.path.exists(f) else None


def _read(path: str) -> pd.DataFrame:
    return pd.read_csv(path, low_memory=False, usecols=lambda c: _norm(c) != "bytecode")


def load_universe(version: str, protocol: str) -> list[str]:
    """All contract addresses submitted for this protocol+version."""
    f = _path(version, protocol, "combined")
    df = _read(f)
    return df[_col(df, "Address")].astype(str).tolist()


def load_maian(version, protocol):
    f = _path(version, protocol, "maian_dataset")
    if not f:
        return {}, set()
    df = _read(f)
    a = _col(df, "Address")
    findings = defaultdict(set)
    for _, r in df.iterrows():
        for raw, cat in MAIAN_MAP.items():
            c = _col(df, raw)
            if c is not None and _truthy(r[c]):
                findings[str(r[a])].add(cat)
    return findings, set(df[a].astype(str))


def _long_labels(df, addr_col, label_col):
    findings = defaultdict(set)
    for _, r in df.iterrows():
        raw = r[label_col]
        if pd.isna(raw):
            continue
        for part in str(raw).split(";"):
            cat = None
            key = part.strip().lower()
            for table in (MYTHRIL_MAP, OYENTE_MAP):
                if key in table:
                    cat = table[key]
                    break
            if cat is None:
                cat = OYENTE_MAP.get(_norm(part)) or MYTHRIL_MAP.get(_norm(part))
            if cat:
                findings[str(r[addr_col])].add(cat)
    return findings


def load_mythril(version, protocol):
    f = _path(version, protocol, "mythril_dataset")
    if not f:
        return {}, set()
    df = _read(f)
    a = _col(df, "Address")
    v = _col(df, "Vulnerability", "vulnerability_type")
    return _long_labels(df, a, v), set(df[a].astype(str))


def load_oyente(version, protocol):
    f = _path(version, protocol, "oyente_dataset")
    if not f:
        return {}, set()
    df = _read(f)
    a = _col(df, "Address")
    if a is None or df.empty:
        return {}, set()
    v = _col(df, "Vulnerability", "vulnerability_type")
    if v is not None:                                   # long form
        return _long_labels(df, a, v), set(df[a].astype(str))
    findings = defaultdict(set)                          # wide form
    wide = [c for c in df.columns if c != a and _norm(c) in OYENTE_MAP]
    for _, r in df.iterrows():
        for c in wide:
            if _truthy(r[c]):
                findings[str(r[a])].add(OYENTE_MAP[_norm(c)])
    return findings, set(df[a].astype(str))


def load_securify(version, protocol):
    f = _path(version, protocol, "securify_dataset")
    if not f:
        return {}, set()
    df = _read(f)
    a = _col(df, "Address", "address")
    if a is None or df.empty:
        return {}, set()
    findings = defaultdict(set)
    wide = [c for c in df.columns if _norm(c) in SECURIFY_MAP]
    if wide:                                             # per-pattern Yes/No columns
        for _, r in df.iterrows():
            for c in wide:
                if _truthy(r[c]):
                    findings[str(r[a])].add(SECURIFY_MAP[_norm(c)])
    else:                                                # violations / patterns summary
        vio = _col(df, "violations")
        pat = _col(df, "patterns")
        for _, r in df.iterrows():
            has = SECURIFY_PATTERNS_AS_FINDINGS or (vio is not None and float(r[vio] or 0) > 0)
            if not has or pat is None or pd.isna(r[pat]):
                continue
            for part in str(r[pat]).split(";"):
                cat = SECURIFY_MAP.get(_norm(part))
                if cat:
                    findings[str(r[a])].add(cat)
    return findings, set(df[a].astype(str))


LOADERS = {"MAIAN": load_maian, "Mythril": load_mythril,
           "Oyente": load_oyente, "Securify": load_securify}


def build_dataset():
    """
    findings[version][protocol][tool] -> {address: {vuln, ...}}
    ran[version][protocol][tool]      -> addresses of this protocol the tool reported on
    universe[version][protocol]       -> list of addresses

    A tool file whose addresses do not belong to the protocol it is filed under
    is discarded rather than silently counted as zero detections -- see the
    obs_ccip MAIAN export, which is a byte-for-byte copy of the Hyperlane one.
    """
    findings, ran, universe = {}, {}, {}
    for version in ("original", "obfuscated"):
        findings[version], ran[version], universe[version] = {}, {}, {}
        for p in PROTOCOLS:
            universe[version][p] = load_universe(version, p)
            u = set(universe[version][p])
            findings[version][p], ran[version][p] = {}, {}
            for t in TOOLS:
                fnd, seen = LOADERS[t](version, p)
                findings[version][p][t] = {a: v for a, v in fnd.items() if a in u}
                ran[version][p][t] = seen & u
    return findings, ran, universe


def has_data(ran, version, protocol, tool) -> bool:
    """True when the tool actually produced results for this protocol+version."""
    return len(ran[version][protocol][tool]) > 0


# --------------------------------------------------------------------------
# Metrics
# --------------------------------------------------------------------------

def efficiency_table(findings, ran, universe, version):
    """% of submitted contracts each tool flags, per protocol. NaN = no results."""
    rows = []
    for p in PROTOCOLS:
        n = len(universe[version][p]) or 1
        row = {"Protocol": p, "N": len(universe[version][p])}
        for t in TOOLS:
            if not has_data(ran, version, p, t):
                row[t] = np.nan
                continue
            flagged = sum(1 for a in universe[version][p] if findings[version][p][t].get(a))
            row[t] = 100.0 * flagged / n
        rows.append(row)
    df = pd.DataFrame(rows).set_index("Protocol")
    pooled = {}
    for t in TOOLS:
        covered = [p for p in PROTOCOLS if has_data(ran, version, p, t)]
        total = sum(len(universe[version][p]) for p in covered)
        flagged = sum(1 for p in covered for a in universe[version][p]
                      if findings[version][p][t].get(a))
        pooled[t] = 100.0 * flagged / total if total else np.nan
    pooled["N"] = sum(len(universe[version][p]) for p in PROTOCOLS)
    df.loc["All"] = pooled
    return df


def per_vuln_matrix(findings, ran, universe, version, protocol):
    """tool x vulnerability, as % of that protocol's submitted contracts."""
    n = len(universe[version][protocol]) or 1
    m = pd.DataFrame(0.0, index=TOOLS, columns=VULNS)
    for t in TOOLS:
        if not has_data(ran, version, protocol, t):
            m.loc[t, :] = np.nan
            continue
        fnd = findings[version][protocol][t]
        for a in universe[version][protocol]:
            for v in fnd.get(a, ()):
                m.loc[t, v] += 1
    return 100.0 * m / n


def vuln_prevalence(findings, universe, version, protocol):
    """% of contracts flagged for each vulnerability by any tool."""
    n = len(universe[version][protocol]) or 1
    out = pd.Series(0.0, index=VULNS)
    for a in universe[version][protocol]:
        hit = set()
        for t in TOOLS:
            hit |= findings[version][protocol][t].get(a, set())
        for v in hit:
            out[v] += 1
    return 100.0 * out / n


def matched_pairs(universe):
    """Addresses present in both the original and the obfuscated run."""
    return {p: sorted(set(universe["original"][p]) & set(universe["obfuscated"][p]))
            for p in PROTOCOLS}


def persistence_table(findings, ran, pairs):
    """
    Per protocol x tool on matched pairs:
      orig, persisted, new, lost, persist %, orig eff %, obf eff %.
    Rows where either run produced no results for that tool are marked No_Data
    and carry NaN rates -- "the tool never reported" is not "the tool found
    nothing", and conflating them fabricates a robustness result.
    """
    rows = []
    for p in PROTOCOLS:
        addrs = pairs[p]
        for t in TOOLS:
            ok = has_data(ran, "original", p, t) and has_data(ran, "obfuscated", p, t)
            o, b = findings["original"][p][t], findings["obfuscated"][p][t]
            of = {a for a in addrs if o.get(a)}
            bf = {a for a in addrs if b.get(a)}
            rows.append({
                "Protocol": p, "Tool": t, "Pairs": len(addrs), "No_Data": not ok,
                "Orig": len(of) if ok else np.nan,
                "Persisted": len(of & bf) if ok else np.nan,
                "New": len(bf - of) if ok else np.nan,
                "Lost": len(of - bf) if ok else np.nan,
                "Persist_%": (100.0 * len(of & bf) / len(of)) if (ok and of) else np.nan,
                "Orig_Eff_%": (100.0 * len(of) / len(addrs)) if (ok and addrs) else np.nan,
                "Obf_Eff_%": (100.0 * len(bf) / len(addrs)) if (ok and addrs) else np.nan,
            })
    df = pd.DataFrame(rows)
    df["Drop_pts"] = df["Orig_Eff_%"] - df["Obf_Eff_%"]
    return df


# --------------------------------------------------------------------------
# Figures
# --------------------------------------------------------------------------

ND_TEXT = "no data — tool produced no results for this protocol"


def _hatch_missing(ax, vals):
    """Texture on missing cells, so 'no data' never reads as a pale low value."""
    for i in range(vals.shape[0]):
        for j in range(vals.shape[1]):
            if np.isnan(vals[i, j]):
                ax.add_patch(plt.Rectangle((j - 0.5, i - 0.5), 1, 1, facecolor="none",
                                           edgecolor="#c9c8c2", hatch="////",
                                           linewidth=0, zorder=2))


def _zero_stub(ax, cx, half_width, color):
    """A hairline at y=0 marking a tool that ran and flagged nothing."""
    ax.plot([cx - half_width, cx + half_width], [0, 0], color=color,
            linewidth=2.6, solid_capstyle="butt", zorder=4)


def fig01_overall_efficiency(eff_o):
    order = PROTOCOLS + ["All"]
    x = np.arange(len(order), dtype=float)
    w = 0.19
    fig, ax = plt.subplots(figsize=(11.5, 5.4))
    for i, t in enumerate(TOOLS):
        off = (i - (len(TOOLS) - 1) / 2) * w
        vals = eff_o.loc[order, t].values.astype(float)
        bars = ax.bar(x + off, np.nan_to_num(vals), w * 0.9, color=TOOL_COLOR[t],
                      label=t, edgecolor=SURFACE, linewidth=1.6, zorder=3)
        for rect, v in zip(bars, vals):
            cx = rect.get_x() + rect.get_width() / 2
            if np.isnan(v):
                ax.text(cx, 1.5, "n/d", ha="center", va="bottom", fontsize=6.8,
                        color=MUTED, rotation=90)
            elif v < 0.4:
                _zero_stub(ax, cx, rect.get_width() / 2, TOOL_COLOR[t])
            else:
                ax.text(cx, v + 1.6, f"{v:.0f}", ha="center", va="bottom",
                        fontsize=7.6, color=INK_2)
    ax.set_xticks(x)
    ax.set_xticklabels([f"{p}\nn={int(eff_o.loc[p,'N'])}" for p in order])
    ax.set_ylabel("Contracts flagged (% of submitted)")
    ax.set_ylim(0, 105)
    ax.axvline(len(PROTOCOLS) - 0.5, color=AXIS, linewidth=0.8, linestyle=(0, (4, 4)), zorder=1)
    style_axes(ax)
    ax.legend(frameon=False, ncol=4, loc="upper center", bbox_to_anchor=(0.5, 1.09))
    figtitle(fig, "Detection efficiency by tool and bridge protocol",
             "Original (unobfuscated) bytecode. Efficiency = share of submitted contracts the tool flags with at least one finding.")
    footnote(fig, f"A flat coloured stub on the baseline means the tool ran and flagged nothing.  n/d = {ND_TEXT}; 'All' pools only the protocols that tool covered.")
    fig.subplots_adjust(top=0.80)
    fig.savefig(os.path.join(OUT, "01_overall_efficiency_all_protocols.png"))
    plt.close(fig)


def _per_vuln_fig(mat, protocol, version, fname):
    x = np.arange(len(VULNS), dtype=float)
    w = 0.20
    fig, ax = plt.subplots(figsize=(11.5, 4.9))
    top = max(np.nanmax(mat.values) if np.isfinite(mat.values).any() else 0.0, 1.0)
    missing = []
    for i, t in enumerate(TOOLS):
        off = (i - (len(TOOLS) - 1) / 2) * w
        vals = mat.loc[t, VULNS].values.astype(float)
        if np.isnan(vals).all():
            missing.append(t)
            continue
        bars = ax.bar(x + off, vals, w * 0.9, color=TOOL_COLOR[t], label=t,
                      edgecolor=SURFACE, linewidth=1.4, zorder=3)
        for rect, v in zip(bars, vals):
            cx = rect.get_x() + rect.get_width() / 2
            if v > top * 0.03:
                ax.text(cx, v + top * 0.02, f"{v:.0f}", ha="center", va="bottom",
                        fontsize=7.2, color=INK_2)
            else:
                _zero_stub(ax, cx, rect.get_width() / 2, TOOL_COLOR[t])
    ax.set_xticks(x)
    ax.set_xticklabels([VULN_LABELS[v] for v in VULNS])
    ax.set_ylabel("Contracts flagged (%)")
    ax.set_ylim(0, max(top * 1.20, 5))
    style_axes(ax)
    handles = [Patch(facecolor=TOOL_COLOR[t], label=t) for t in TOOLS if t not in missing]
    handles += [Patch(facecolor="none", edgecolor=AXIS, hatch="///",
                      label=f"{t} (no data)") for t in missing]
    ax.legend(handles=handles, frameon=False, ncol=4, loc="upper center",
              bbox_to_anchor=(0.5, 1.11))
    label = "original" if version == "original" else "obfuscated"
    figtitle(fig, f"{protocol} — detections per vulnerability class ({label} bytecode)",
             f"Percentage of {protocol}'s submitted contracts each tool flags for each SmartBugs class. Every tool keeps its slot in each group, so the ten per-protocol figures line up.")
    note = "A stub on the baseline = the tool ran and never triggered that class."
    if missing:
        note += ("  No data at all for " + ", ".join(missing) +
                 " — that tool produced no results for this protocol+version, which is not the same as finding nothing.")
    footnote(fig, note)
    fig.subplots_adjust(top=0.79)
    fig.savefig(os.path.join(OUT, fname))
    plt.close(fig)


def fig04_tool_trend(pairs, pers):
    order = PROTOCOLS + ["All"]
    fig, axes = plt.subplots(1, len(order), figsize=(15.0, 4.8), sharey=True)

    pooled = {}
    for t in TOOLS:
        sub = pers[(pers.Tool == t) & (~pers.No_Data)]
        tot = sub["Pairs"].sum()
        if not tot:
            pooled[t] = (np.nan, np.nan)
            continue
        o = sub["Orig"].sum()
        b = sub["Persisted"].sum() + sub["New"].sum()
        pooled[t] = (100.0 * o / tot, 100.0 * b / tot)

    for ax, p in zip(axes, order):
        missing = []
        if p == "All":
            label = "each tool pooled over\nthe bridges it covered"
        else:
            label = f"{len(pairs[p])} matched pairs"
        for t in TOOLS:
            if p == "All":
                yo, yb = pooled[t]
            else:
                r = pers[(pers.Protocol == p) & (pers.Tool == t)].iloc[0]
                yo, yb = r["Orig_Eff_%"], r["Obf_Eff_%"]
            if np.isnan(yo) or np.isnan(yb):
                missing.append(t)
                continue
            ax.plot([0, 1], [yo, yb], color=TOOL_COLOR[t], linewidth=2.0,
                    marker="o", markersize=6.5, markeredgecolor=SURFACE,
                    markeredgewidth=1.4, zorder=3)
        ax.set_xlim(-0.35, 1.35)
        ax.set_xticks([0, 1])
        ax.set_xticklabels(["Orig.", "Obf."])
        ax.set_title(f"{p}\n{label}", fontsize=10, color=INK, pad=8)
        if missing:
            ax.text(0.5, -0.16, "no data: " + ", ".join(missing), transform=ax.transAxes,
                    ha="center", va="top", fontsize=7.2, color=MUTED)
        style_axes(ax)
    axes[0].set_ylabel("Contracts flagged (%)")
    axes[0].set_ylim(-4, 108)
    handles = [plt.Line2D([], [], color=TOOL_COLOR[t], lw=2.4, marker="o",
                          markersize=6.5, label=t) for t in TOOLS]
    fig.legend(handles=handles, frameon=False, ncol=4, loc="upper center",
               bbox_to_anchor=(0.5, 0.885))
    figtitle(fig, "What obfuscation does to each tool",
             "Detection efficiency before and after BOSC obfuscation, on the contracts matched in both runs. A steep fall means obfuscation blinded the tool.")
    fig.subplots_adjust(top=0.66, bottom=0.20, wspace=0.16)
    fig.savefig(os.path.join(OUT, "04_tool_trend_orig_vs_obf.png"))
    plt.close(fig)


def _heatmap(mat, cover, title, subtitle, fname, note=None):
    fig, ax = plt.subplots(figsize=(11.0, 3.8))
    vals = mat.values.astype(float)
    vmax = max(np.nanmax(vals) if np.isfinite(vals).any() else 0.0, 1.0)
    cmap = SEQ_BLUE.copy()
    cmap.set_bad(ND_FILL)
    im = ax.imshow(np.ma.masked_invalid(vals), cmap=cmap, vmin=0, vmax=vmax, aspect="auto")
    _hatch_missing(ax, vals)
    ax.set_xticks(np.arange(len(VULNS)))
    ax.set_xticklabels([VULN_LABELS[v] for v in VULNS])
    ax.set_yticks(np.arange(len(TOOLS)))
    ax.set_yticklabels([f"{t}\n{cover[t]}/5 protocols" for t in TOOLS], fontsize=9, color=INK)
    ax.set_xticks(np.arange(-0.5, len(VULNS), 1), minor=True)
    ax.set_yticks(np.arange(-0.5, len(TOOLS), 1), minor=True)
    ax.grid(which="minor", color=SURFACE, linewidth=2.0)
    ax.tick_params(which="minor", length=0)
    ax.tick_params(length=0)
    for s in ax.spines.values():
        s.set_visible(False)
    for i in range(vals.shape[0]):
        for j in range(vals.shape[1]):
            v = vals[i, j]
            if np.isnan(v):
                ax.text(j, i, "n/d", ha="center", va="center", fontsize=7.4, color=MUTED)
            elif v > 0:
                ax.text(j, i, f"{v:.0f}", ha="center", va="center", fontsize=8.4,
                        color="#ffffff" if v > vmax * 0.55 else INK)
    cb = fig.colorbar(im, ax=ax, fraction=0.022, pad=0.015)
    cb.set_label("Mean % of contracts flagged", fontsize=8.5, color=INK_2)
    cb.outline.set_visible(False)
    cb.ax.tick_params(length=0, labelsize=8, colors=MUTED)
    figtitle(fig, title, subtitle)
    if note:
        footnote(fig, note)
    fig.subplots_adjust(top=0.82, bottom=0.16)
    fig.savefig(os.path.join(OUT, fname))
    plt.close(fig)


def fig07_radar(findings, universe):
    n = len(VULNS)
    ang = np.linspace(0, 2 * np.pi, n, endpoint=False)
    ang_c = np.concatenate([ang, ang[:1]])
    fig, axes = plt.subplots(1, 5, figsize=(17.0, 4.7), subplot_kw={"polar": True})
    prof = {p: vuln_prevalence(findings, universe, "original", p) for p in PROTOCOLS}
    vmax = max(10.0, max(s.max() for s in prof.values()))
    vmax = float(np.ceil(vmax / 10.0) * 10)
    for ax, p in zip(axes, PROTOCOLS):
        vals = prof[p].reindex(VULNS).values
        v = np.concatenate([vals, vals[:1]])
        ax.fill(ang_c, v, color=ACCENT, alpha=0.18, zorder=2)
        ax.plot(ang_c, v, color=ACCENT, linewidth=2.0, zorder=3)
        ax.plot(ang, vals, linestyle="none", marker="o", markersize=4.5,
                color=ACCENT, markeredgecolor=SURFACE, markeredgewidth=1.0, zorder=4)
        for a, val in zip(ang, vals):
            if val > 0:
                ax.text(a, val + vmax * 0.09, f"{val:.0f}", ha="center", va="center",
                        fontsize=7.4, color=INK, zorder=5)
        ax.set_xticks(ang)
        ax.set_xticklabels([VULN_LABELS[x].replace("\n", " ") for x in VULNS],
                           fontsize=6.8, color=MUTED)
        ax.tick_params(axis="x", pad=6)
        ax.set_ylim(0, vmax * 1.12)
        ax.set_yticks([vmax * 0.5, vmax])
        ax.set_yticklabels([f"{vmax*0.5:.0f}%", f"{vmax:.0f}%"], fontsize=6.4, color=MUTED)
        ax.set_rlabel_position(96)
        ax.grid(color=GRID, linewidth=0.8)
        ax.spines["polar"].set_color(GRID)
        ax.set_title(f"{p}\nn={len(universe['original'][p])}", fontsize=10.5, color=INK, pad=26)
    figtitle(fig, "Vulnerability profile of each bridge (original bytecode)",
             "Share of the protocol's contracts flagged for each class by at least one tool. All five panels share one radial scale, so shapes are directly comparable.")
    footnote(fig, "Detection is concentrated in a few classes, so each profile reads as spokes rather than a filled polygon — figure 05 shows the same data as a heatmap.")
    fig.subplots_adjust(top=0.74, bottom=0.08, wspace=0.55)
    fig.savefig(os.path.join(OUT, "07_radar_orig_per_protocol.png"))
    plt.close(fig)


def fig08_nv_positives(pers):
    x = np.arange(len(PROTOCOLS), dtype=float)
    fig, ax = plt.subplots(figsize=(10.5, 5.0))
    bottom = np.zeros(len(PROTOCOLS))
    for t in TOOLS:
        vals = np.nan_to_num(np.array(
            [pers[(pers.Protocol == p) & (pers.Tool == t)]["New"].iloc[0]
             for p in PROTOCOLS], dtype=float))
        ax.bar(x, vals, 0.56, bottom=bottom, color=TOOL_COLOR[t], label=t,
               edgecolor=SURFACE, linewidth=2.0, zorder=3)
        for xi, (b, v) in enumerate(zip(bottom, vals)):
            if v > 0:
                ax.text(xi, b + v / 2, f"{int(v)}", ha="center", va="center",
                        fontsize=8.2, color="#ffffff" if t != "Securify" else INK)
        bottom += vals
    for xi, tot in enumerate(bottom):
        pairs = int(pers[pers.Protocol == PROTOCOLS[xi]]["Pairs"].iloc[0])
        ax.text(xi, tot + max(bottom.max() * 0.02, 0.2),
                f"{int(tot)}  ({100*tot/max(pairs,1):.0f}% of {pairs} pairs)",
                ha="center", va="bottom", fontsize=8.4, color=INK_2)
    ax.set_xticks(x)
    ax.set_xticklabels(PROTOCOLS)
    ax.set_ylabel("Contracts newly flagged after obfuscation")
    ax.set_ylim(0, max(bottom.max() * 1.22, 1))
    style_axes(ax)
    ax.legend(frameon=False, ncol=4, loc="upper center", bbox_to_anchor=(0.5, 1.08))
    figtitle(fig, "Novel positives introduced by obfuscation",
             "Matched contracts a tool did NOT flag originally but does flag after BOSC obfuscation — detections created by the transformation, not found by it.")
    nd = sorted({f"{r.Protocol}/{r.Tool}" for r in pers.itertuples() if r.No_Data})
    footnote(fig, "Counted per tool, so one contract can appear in more than one segment."
             + ("  Excluded for lack of data: " + ", ".join(nd) + "." if nd else ""))
    fig.subplots_adjust(top=0.80)
    fig.savefig(os.path.join(OUT, "08_nv_positives_stacked.png"))
    plt.close(fig)


def fig09_drop_heatmap(pers):
    mat = pers.pivot(index="Tool", columns="Protocol", values="Drop_pts").reindex(index=TOOLS, columns=PROTOCOLS)
    lim = float(np.nanmax(np.abs(mat.values))) or 1.0
    fig, ax = plt.subplots(figsize=(8.6, 4.2))
    cmap = DIV_BR.copy()
    cmap.set_bad(ND_FILL)
    im = ax.imshow(np.ma.masked_invalid(mat.values.astype(float)), cmap=cmap,
                   norm=TwoSlopeNorm(vcenter=0, vmin=-lim, vmax=lim), aspect="auto")
    _hatch_missing(ax, mat.values.astype(float))
    ax.set_xticks(np.arange(len(PROTOCOLS)))
    ax.set_xticklabels(PROTOCOLS, fontsize=9.5, color=INK)
    ax.set_yticks(np.arange(len(TOOLS)))
    ax.set_yticklabels(TOOLS, fontsize=10, color=INK)
    ax.set_xticks(np.arange(-0.5, len(PROTOCOLS), 1), minor=True)
    ax.set_yticks(np.arange(-0.5, len(TOOLS), 1), minor=True)
    ax.grid(which="minor", color=SURFACE, linewidth=2.0)
    ax.tick_params(which="minor", length=0)
    ax.tick_params(length=0)
    for s in ax.spines.values():
        s.set_visible(False)
    nd = {(r.Tool, r.Protocol) for r in pers.itertuples() if r.No_Data}
    for i, t in enumerate(TOOLS):
        for j, p in enumerate(PROTOCOLS):
            v = mat.values[i, j]
            if np.isnan(v):
                ax.text(j, i, "n/d" if (t, p) in nd else "n/a", ha="center",
                        va="center", fontsize=8, color=MUTED)
                continue
            ax.text(j, i, f"{v:+.0f}", ha="center", va="center", fontsize=9,
                    color="#ffffff" if abs(v) > lim * 0.55 else INK)
    cb = fig.colorbar(im, ax=ax, fraction=0.03, pad=0.02)
    cb.set_label("Efficiency drop (percentage points)", fontsize=8.5, color=INK_2)
    cb.outline.set_visible(False)
    cb.ax.tick_params(length=0, labelsize=8, colors=MUTED)
    figtitle(fig, "Efficiency lost to obfuscation",
             "Original minus obfuscated detection rate on matched contracts. Red = detection lost; blue = the tool flags more after obfuscation.")
    footnote(fig, f"n/d = {ND_TEXT}.   n/a = tool ran on both sides and flagged nothing either time.")
    fig.subplots_adjust(top=0.80, bottom=0.16)
    fig.savefig(os.path.join(OUT, "09_efficiency_drop_heatmap.png"))
    plt.close(fig)


def fig10_robustness(pers):
    x = np.arange(len(PROTOCOLS), dtype=float)
    w = 0.19
    fig, (ax, ax2) = plt.subplots(1, 2, figsize=(13.0, 5.0),
                                  gridspec_kw={"width_ratios": [3.1, 1.0]})
    for i, t in enumerate(TOOLS):
        off = (i - (len(TOOLS) - 1) / 2) * w
        vals, tags = [], []
        for p in PROTOCOLS:
            r = pers[(pers.Protocol == p) & (pers.Tool == t)].iloc[0]
            vals.append(r["Persist_%"])
            tags.append("n/d" if r["No_Data"] else ("n/a" if not r["Orig"] else None))
        vals = np.array(vals, dtype=float)
        bars = ax.bar(x + off, np.nan_to_num(vals), w * 0.9, color=TOOL_COLOR[t],
                      label=t, edgecolor=SURFACE, linewidth=1.5, zorder=3)
        for rect, v, tag in zip(bars, vals, tags):
            cx = rect.get_x() + rect.get_width() / 2
            if np.isnan(v):
                ax.text(cx, 1.5, tag, ha="center", va="bottom", fontsize=6.8,
                        color=MUTED, rotation=90)
            else:
                ax.text(cx, v + 1.8, f"{v:.0f}", ha="center", va="bottom",
                        fontsize=7.4, color=INK_2)
    ax.set_xticks(x)
    ax.set_xticklabels(PROTOCOLS)
    ax.set_ylabel("Persistence (% of original detections retained)")
    ax.set_ylim(0, 108)
    style_axes(ax)
    ax.legend(frameon=False, ncol=4, loc="upper center", bbox_to_anchor=(0.5, 1.08))
    ax.set_title("Per protocol", fontsize=10, color=INK_2, loc="left", pad=26)

    tot, bases = [], []
    for t in TOOLS:
        sub = pers[(pers.Tool == t) & (~pers.No_Data)]
        o, pr = sub["Orig"].sum(), sub["Persisted"].sum()
        bases.append(int(o))
        tot.append(100.0 * pr / o if o else np.nan)
    bars = ax2.bar(np.arange(len(TOOLS)), np.nan_to_num(tot), 0.6,
                   color=[TOOL_COLOR[t] for t in TOOLS], edgecolor=SURFACE,
                   linewidth=1.5, zorder=3)
    for rect, v, o in zip(bars, tot, bases):
        cx = rect.get_x() + rect.get_width() / 2
        ax2.text(cx, (0 if np.isnan(v) else v) + 1.8,
                 "n/a" if np.isnan(v) else f"{v:.0f}%", ha="center", va="bottom",
                 fontsize=8.6, color=INK_2)
        ax2.text(cx, -6.5, f"n={o}", ha="center", va="top", fontsize=7.4, color=MUTED)
    ax2.set_xticks(np.arange(len(TOOLS)))
    ax2.set_xticklabels(TOOLS, fontsize=9)
    ax2.set_ylim(0, 108)
    style_axes(ax2)
    ax2.set_title("All protocols pooled", fontsize=10, color=INK_2, loc="left", pad=26)

    figtitle(fig, "Tool robustness under BOSC obfuscation",
             "Of the contracts a tool flagged in the original run, the share it still flags after obfuscation. Higher is more robust.")
    footnote(fig, f"n/a = the tool ran but flagged nothing originally, so there is no baseline to persist.   n/d = {ND_TEXT}; those protocols are excluded from the pooled bars.")
    fig.subplots_adjust(top=0.78, bottom=0.14, wspace=0.22)
    fig.savefig(os.path.join(OUT, "10_tool_robustness_bar.png"))
    plt.close(fig)


# --------------------------------------------------------------------------

def main():
    os.makedirs(OUT, exist_ok=True)
    findings, ran, universe = build_dataset()

    eff_o = efficiency_table(findings, ran, universe, "original")
    eff_b = efficiency_table(findings, ran, universe, "obfuscated")
    pairs = matched_pairs(universe)
    pers = persistence_table(findings, ran, pairs)

    fig01_overall_efficiency(eff_o)

    per_vuln = {}
    for p in PROTOCOLS:
        mo = per_vuln_matrix(findings, ran, universe, "original", p)
        mb = per_vuln_matrix(findings, ran, universe, "obfuscated", p)
        per_vuln[(p, "original")], per_vuln[(p, "obfuscated")] = mo, mb
        _per_vuln_fig(mo, p, "original", f"02_per_vuln_orig_{p}.png")
        _per_vuln_fig(mb, p, "obfuscated", f"03_per_vuln_obf_{p}.png")

    fig04_tool_trend(pairs, pers)

    # mean over the protocols the tool actually covered; NaN if it covered none
    def avg(version):
        stack = np.array([per_vuln[(p, version)].values.astype(float) for p in PROTOCOLS])
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            m = np.nanmean(stack, axis=0)
        cov = {t: int(sum(has_data(ran, version, p, t) for p in PROTOCOLS)) for t in TOOLS}
        return pd.DataFrame(m, index=TOOLS, columns=VULNS), cov

    avg_o, cov_o = avg("original")
    avg_b, cov_b = avg("obfuscated")
    _heatmap(avg_o, cov_o, "Which tool finds which class — original bytecode",
             "Mean across the bridges each tool covered, of the % of contracts it flags per class. Blank = ran but never triggered.",
             "05_heatmap_orig_avg.png",
             f"n/d = {ND_TEXT}.  The row label gives how many of the five bridges the tool covered.")
    _heatmap(avg_b, cov_b, "Which tool finds which class — obfuscated bytecode",
             "Same measurement after BOSC obfuscation. Compare cell-for-cell with figure 05.",
             "06_heatmap_obf_avg.png",
             f"n/d = {ND_TEXT}.  The row label gives how many of the five bridges the tool covered.")

    fig07_radar(findings, universe)
    fig08_nv_positives(pers)
    fig09_drop_heatmap(pers)
    fig10_robustness(pers)

    # underlying numbers, so every figure is auditable
    cov = []
    for version in ("original", "obfuscated"):
        for p in PROTOCOLS:
            for t in TOOLS:
                u = set(universe[version][p])
                cov.append({"Version": version, "Protocol": p, "Tool": t,
                            "Submitted": len(u),
                            "Reported_on": len(ran[version][p][t]),
                            "Flagged": sum(1 for a in u if findings[version][p][t].get(a)),
                            "Usable": has_data(ran, version, p, t)})
    xlsx = os.path.join(OUT, "plot_source_metrics.xlsx")
    with pd.ExcelWriter(xlsx) as xw:
        eff_o.to_excel(xw, sheet_name="Efficiency_Original")
        eff_b.to_excel(xw, sheet_name="Efficiency_Obfuscated")
        pers.to_excel(xw, sheet_name="Persistence_Matched", index=False)
        pd.DataFrame(cov).to_excel(xw, sheet_name="Tool_Coverage", index=False)
        avg_o.to_excel(xw, sheet_name="Heatmap_Orig_Avg")
        avg_b.to_excel(xw, sheet_name="Heatmap_Obf_Avg")
        for p in PROTOCOLS:
            per_vuln[(p, "original")].to_excel(xw, sheet_name=f"{p}_orig"[:31])
            per_vuln[(p, "obfuscated")].to_excel(xw, sheet_name=f"{p}_obf"[:31])

    print("Figures + plot_source_metrics.xlsx written to", OUT)
    print("\nMatched pairs:", {p: len(v) for p, v in pairs.items()})
    print("\nEfficiency %, original:\n", eff_o.round(1).to_string())
    print("\nEfficiency %, obfuscated:\n", eff_b.round(1).to_string())
    print("\nPersistence:\n", pers.round(1).to_string())


if __name__ == "__main__":
    main()
