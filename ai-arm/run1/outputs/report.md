# UNSW-NB15: normal vs malicious traffic (dur, sbytes, dbytes, spkts, dpkts)

## Setup and data handling
- Files identified by contents: `UNSW_NB15_training-set.csv` = 175,341 rows (56,000 normal / 119,341 malicious); `UNSW_NB15_testing-set.csv` = 82,332 rows (37,000 normal / 45,332 malicious). No missing values in the five features, no duplicate rows. Both have 45 columns.
- Existing-analysis files: none seen in the folder, only the two CSVs and `_action_log.txt` (my own log).
- Environment: see `environment_and_counts.json` (Python/pandas/numpy/scipy/matplotlib versions, OS). Interpreter: `C:\unsw-runs\env\Scripts\python.exe`. Code: `analysis.py`. Console output: `results_stdout.txt` (the shell reported exit code 1 only because matplotlib deprecation warnings went to stderr; all outputs were produced).
- No rows removed, no transformation applied for the statistics. Zeros were kept (they are meaningful: 0 dbytes/dpkts = no reply).

## Methods and why
- The features are extremely right-skewed with many zeros, so I compare medians/IQR and use the Mann-Whitney U test plus Cliff's delta (rank-based effect size, range -1..1; negative = malicious values tend to be lower than normal). Means are shown but are dominated by outliers.
- With n of tens of thousands, p-values are essentially all 0, so they carry no information; effect sizes are what matter.
- RQ2: compare the effect size and direction per feature between partitions, and compare each class's distribution across partitions (KS statistic, Cliff's delta). Also repeated per attack category.
- Figures use log scale, outliers hidden in boxplots.

## RQ1: normal vs malicious (Cliff's delta, malicious vs normal; medians normal -> malicious)

| feature | train delta | test delta | median normal -> malicious (train / test) |
|---|---|---|---|
| dur | -0.285 | -0.354 | 0.0386 -> 0.0 / 0.2228 -> 0.0 |
| sbytes | -0.413 | -0.399 | 1470 -> 200 / 974 -> 200 |
| dbytes | -0.573 | -0.473 | 1112 -> 0 / 354 -> 0 |
| spkts | -0.412 | -0.392 | 12 -> 2 / 10 -> 2 |
| dpkts | -0.566 | -0.475 | 10 -> 0 / 8 -> 0 |

- Typical malicious flows are shorter and smaller, with fewer packets in both directions. The biggest contrast is in the destination side: 65.1% (train) and 65.8% (test) of malicious flows have dbytes = dpkts = 0 (no response), versus 11.9% and 16.7% of normal flows.
- Effects are moderate (|delta| about 0.3 to 0.6), not a clean separation: distributions overlap heavily.
- Means point the other way for some features. Mean sbytes is higher for malicious (11,069 vs 4,106 train; 11,195 vs 4,072 test) despite a lower median, i.e. a minority of malicious flows are very large. Mean dur is higher for malicious in train (1.52 vs 1.02) but about equal in test (1.00 vs 1.01). Mean dbytes/dpkts are lower for malicious. Mean-based statements are therefore unreliable here.
- The malicious class is heterogeneous (`attack_cat_summary`: `attack_category_summary.csv`). Generic, Backdoor, Analysis, DoS and Shellcode are strongly lower than normal on most features (e.g. Generic delta about -0.7 to -0.87). Exploits, Fuzzers and Worms are near zero or slightly positive for duration (Exploits +0.13/+0.15, Worms +0.41/+0.22 train/test) and for several other features. So "malicious is smaller/shorter" is a class-average pattern driven by the large Generic/DoS shares, not a property of every attack type.

## RQ2: consistency across train and test
- Direction: all 5 features have the same sign and similar size in both partitions. Differences in delta are 0.01 to 0.10 (dur 0.07, sbytes 0.01, dbytes 0.10, spkts 0.02, dpkts 0.09). The qualitative finding replicates; magnitudes for dbytes/dpkts are somewhat weaker in test and dur somewhat stronger.
- Per attack category x feature (45 cells): sign agrees in 41 (91.1%). Disagreements: Exploits (dbytes, sbytes, spkts: negative in train, about zero in test, test deltas within +/-0.03) and Worms spkts (-0.06 train, +0.02 test). All are tiny effects crossing zero; no strong effect reverses.
- The partitions are not identically distributed, particularly for normal traffic. Train vs test shift in normal flows has KS 0.12 to 0.18 across features (e.g. normal dbytes: median 1112 vs 354, KS 0.177), whereas malicious flows are much more stable (KS 0.01 to 0.075). Hence the effect-size differences in RQ2 come mainly from the normal class changing, which also drives the differing normal medians above.
- Class mix differs: normal 31.9% in train vs 44.9% in test; Exploits 19.0% vs 13.5%, Fuzzers 10.4% vs 7.4%. Pooled malicious-vs-normal contrasts partly reflect this mix.

## Caveats
- This is descriptive, with cross-sectional flow records; I did not model or classify. Large n makes any difference "significant", so interpret effect sizes only.
- The official split is not a random split of one pool (the normal distributions differ), so "consistency" here means consistency across a deliberately/incidentally different partition, which is a fairly strict test; the results nevertheless held in direction.
- Features are heavily tied/zero-inflated (dur = 0 in some malicious flows, probably reflecting timestamp resolution), which limits the interpretation of duration.
- Differences are in single marginal features; no multivariate or per-protocol/service control, so protocol composition could explain part of the differences. The dataset is synthetic testbed traffic, so generalization to real networks is not established.
- Per-category figures for small categories (Worms, Shellcode, Backdoor, Analysis each make up about 1% or less of rows; exact counts are in `attack_category_summary.csv`) are noisy.
- Number of tests was large; no multiplicity correction needed as conclusions rely on effect sizes, not p-values.

## Files created
analysis.py, report.md, rq1_rq2_feature_summary.csv, rq2_consistency.csv, attack_category_summary.csv, attack_category_consistency.csv, class_mix.csv, environment_and_counts.json, results_stdout.txt, fig_boxplots.png, fig_effect_sizes.png, _action_log.txt (also edited)
