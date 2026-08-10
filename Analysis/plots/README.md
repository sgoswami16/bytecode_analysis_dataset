# Vulnerability / detection-efficiency figures

Regenerate everything with:

```
python3 Analysis/plots/generate_vuln_efficiency_plots.py
```

The unit of comparison is the bridge **protocol** (Axelar, Wormhole, LayerZero,
Hyperlane, CCIP), replacing the B01..B05 batches used in the source-code phase.

## Figures

| File | What it shows |
|---|---|
| `01_overall_efficiency_all_protocols.png` | Detection efficiency per tool x protocol, original bytecode |
| `02_per_vuln_orig_<PROTOCOL>.png` (x5) | Per-vulnerability detection, original bytecode |
| `03_per_vuln_obf_<PROTOCOL>.png` (x5) | Per-vulnerability detection, obfuscated bytecode |
| `04_tool_trend_orig_vs_obf.png` | Efficiency slope, original -> obfuscated, per protocol |
| `05_heatmap_orig_avg.png` | Tool x vulnerability, averaged over protocols, original |
| `06_heatmap_obf_avg.png` | Same, obfuscated |
| `07_radar_orig_per_protocol.png` | Vulnerability profile per protocol, original |
| `08_nv_positives_stacked.png` | Novel positives created by obfuscation, by tool |
| `09_efficiency_drop_heatmap.png` | Efficiency drop in percentage points, tool x protocol |
| `10_tool_robustness_bar.png` | Persistence % per tool under obfuscation |

`plot_source_metrics.xlsx` carries the numbers behind every figure, so each one
is auditable without rerunning the script.

## Definitions

- **Detection efficiency %** — share of the protocol's *submitted* contracts a
  tool flags with at least one finding. There is no ground-truth vulnerability
  label for deployed bridge contracts, so this is a detection rate, not a
  recall against known bugs.
- **Persistence %** — of the contracts a tool flagged in the original run, the
  share it still flags after obfuscation. Computed on matched addresses only.
- **Novel positives** — matched contracts flagged after obfuscation but not
  before. Detections the transformation created, rather than ones it revealed.
- **Efficiency drop (pts)** — original minus obfuscated efficiency, on matched
  contracts.

## Reading the "missing" markers

`n/d` (no data, hatched cells / hollow slots) means the tool produced **no
results at all** for that protocol+version. `n/a` means it ran but had no
baseline to persist. A zero-height bar with a coloured stub on the baseline
means it ran and genuinely flagged nothing. These three are not the same thing
and are never merged.

## Data issues found while building these

1. `smartbug/obfuscated/ccip/obs_ccip_maian_dataset.csv` is **byte-identical to
   the Hyperlane file** (same md5, same 37 Hyperlane addresses). CCIP therefore
   has no obfuscated MAIAN results; it is plotted as `n/d`, not as 0%.
2. The obfuscated Securify exports for CCIP, Hyperlane, LayerZero and Wormhole
   repeat all eight pattern names in the `patterns` column on every row with
   `violations = warnings = conflicts = 0`. That is the list of patterns
   *checked*, not *violated*. Counting it as findings (as
   `Analysis/combined/Final_Original_vs_Obfuscated_Analysis_Report.xlsx` does)
   credits Securify with eight detections on every obfuscated contract and makes
   it look like obfuscation *improved* Securify. Set
   `SECURIFY_PATTERNS_AS_FINDINGS = True` in the script to reproduce that.
3. Oyente results exist only for Axelar on the obfuscated side (all negative);
   the other four obfuscated Oyente exports are empty files.
4. Figures are built from the raw per-tool exports rather than the aggregated
   workbooks, because the workbooks store one tool per (contract, vulnerability)
   cell and so lose co-detections.
