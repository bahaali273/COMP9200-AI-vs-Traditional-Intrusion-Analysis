# UNSW-NB15: normal vs malicious traffic, and consistency across partitions

All numbers come from `analysis.py` (run in this session); raw output is in `analysis_output.txt` and the CSVs listed at the end.

## Setup and data handling
- Folder contents: two CSVs plus `_action_log.txt` (the operator's log). I saw no pre-existing analysis, notebook, README or results file.
- Identification by contents: `UNSW_NB15_training-set.csv` has 175,341 rows (the larger one, treated as train); `UNSW_NB15_testing-set.csv` has 82,332 rows (test). Both have the same 45 columns.
- Environment: Python 3.12.10, pandas 2.2.3, numpy 2.2.6, scipy 1.15.3, matplotlib 3.10.3, Windows 11.
- Quality checks: no missing or negative values in the five variables. `label` and `attack_cat` agree (Normal <=> label 0) in both files. No rows were removed.
- Malicious share: train 68.1% (119,341 / 175,341), test 55.1% (45,332 / 82,332). The class mix differs between the partitions.
- Many values are zero. Zero `dbytes` rows: 84,282 in train, 36,006 in test. Zero `dur`: 2,657 in train, 950 in test.
- Many rows are exact duplicates (ignoring `id`): 67,601 in train, 26,387 in test. I kept them, because they are part of the official files. This means observations are not independent, and p-values are overstated.
- Method choice: all five variables are extremely right-skewed and heavy-tailed, with many zeros. So I use medians, IQRs and a rank-based effect size, Cliff's delta (malicious vs normal), with the Mann-Whitney U test. Negative delta means malicious values tend to be smaller. Means are given in `rq1_summary.csv` but are dominated by outliers.
- With samples this large, p-values are all ~0 and uninformative. I focus on effect sizes. I computed bootstrap 95% CIs for delta (200 resamples of 3,000 per class, seed 42), in `rq1_cliff_bootstrap_ci.csv`.
- Thresholds: I read |delta| as a rough guide only (about 0.15 small, 0.33 medium, 0.47 large; these are conventional rules of thumb, not tested here).

## RQ1: normal vs malicious (medians; Cliff's delta, malicious vs normal)

| variable | train median normal | train median mal | train delta | test median normal | test median mal | test delta |
|---|---|---|---|---|---|---|
| dur (s) | 0.0386 | 0.000009 | -0.285 | 0.2228 | 0.00001 | -0.355 |
| sbytes | 1470 | 200 | -0.413 | 974 | 200 | -0.399 |
| dbytes | 1112 | 0 | -0.573 | 354 | 0 | -0.473 |
| spkts | 12 | 2 | -0.412 | 10 | 2 | -0.392 |
| dpkts | 10 | 0 | -0.566 | 8 | 0 | -0.475 |

Finding: in typical terms, malicious flows are shorter, smaller and have fewer packets in both directions than normal flows. The difference is largest for the destination side (`dbytes`, `dpkts`: delta about -0.47 to -0.57), meaning malicious flows often get little or no response. Medians for `dbytes` and `dpkts` of malicious flows are 0. The bootstrap CIs are all well away from zero (e.g. train dbytes -0.594 to -0.550).

Caveat on means: the picture is not uniform in the tails. Mean `sbytes` is higher for malicious (about 11,000 vs 4,100 in train) even though the median is lower, so a few very large malicious flows pull the mean up. Mean `dur` is also higher for malicious in train (1.52 vs 1.02) but not in test (1.00 vs 1.01). "Malicious is smaller" is therefore a statement about the typical flow, not about all flows.

Per attack category (`rq1_by_attack_cat.csv`): the pooled malicious result hides heterogeneity. For example, Exploits is near normal in test (|delta| < 0.03 for several variables), while DoS and Analysis are strongly smaller on destination variables or duration. Worms have positive deltas for some variables (but n is only 130 / 44). The pooled "malicious" class is a mixture dominated by Generic, Exploits and Fuzzers.

## RQ2: consistency across partitions

- Direction is the same in both partitions for all 5 variables (`rq2_consistency.csv`). Effect sizes are similar for sbytes (-0.413 vs -0.399) and spkts (-0.412 vs -0.392). They differ more for dbytes (-0.573 vs -0.473), dpkts (-0.566 vs -0.475) and dur (-0.285 vs -0.355). Differences of about 0.07 to 0.10 are larger than the bootstrap CI half-widths (about 0.02 to 0.03) for dbytes, dpkts and dur, so they are likely real in the sense of sampling noise, but small in magnitude.
- Where the shift comes from (`rq2_class_shift.csv`): malicious traffic is nearly identical across partitions (|delta test vs train| <= 0.05, KS statistic <= 0.075). Normal traffic shifts more (KS 0.12 to 0.18; e.g. median `dbytes` 1112 in train vs 354 in test, median `dur` 0.039 vs 0.223). So the change in contrast is mostly driven by the normal class, which differs in the test partition.
- By attack category (`rq2_attack_cat_consistency.csv`): no category with |delta| > 0.1 in both partitions changes sign. The largest differences are for Analysis `dur` (-0.35 train vs -0.68 test; difference 0.33), Exploits `dbytes` (-0.26 vs +0.02) and Exploits `dpkts` (-0.27 vs -0.01). Category-level conclusions are thus less stable than the pooled one, particularly for Exploits.

Answer to RQ2: yes in direction and approximately in size for the pooled malicious vs normal contrast (same sign for all five variables, effect sizes within about 0.1). Magnitudes are not identical, and some category-level contrasts moved a lot.

## Caveats
- Rows are heavily duplicated and flows may be correlated (e.g. repeated scans/DoS from the same sources), so p-values and CIs treat the data as more independent than it is. The CIs I computed use random resampling and share this issue.
- The training and testing sets are the official partitions, not random splits of one sample: class balance and normal-traffic composition differ, so "consistency" here partly measures dataset construction. Agreement does not show the findings generalise to other networks.
- These are descriptive associations on five variables only. No other features were considered, and no classifier was built. The synthetic, lab-generated nature of the data limits real-world inference.
- The bootstrap CIs used subsamples of 3,000 per class, so they are wider than a full-sample CI would be.
- I did not adjust for multiple comparisons; the key results are far from borderline.
- Zero-inflated `dbytes`/`dpkts` and `dur` (tiny values) mean medians of 0 or ~1e-5 are partly a feature of one-sided or failed connections, which I did not analyse separately.

## Files created
- `analysis.py` (code)
- `analysis_output.txt` (console output of the run)
- `results_meta.json` (environment, QA)
- `rq1_summary.csv`, `rq1_cliff_bootstrap_ci.csv`, `rq1_by_attack_cat.csv`
- `rq2_consistency.csv`, `rq2_class_shift.csv`, `rq2_attack_cat_consistency.csv`
- `fig_boxplots.png`, `fig_effect_sizes.png`
- `report.md`
- (`_action_log.txt` was provided by the operator and appended to)
