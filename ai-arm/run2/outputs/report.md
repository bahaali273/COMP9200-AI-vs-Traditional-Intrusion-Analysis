# UNSW-NB15: normal vs malicious traffic, training vs testing partition

## Housekeeping
- Files: `UNSW_NB15_training-set.csv` (175,341 rows) and `UNSW_NB15_testing-set.csv` (82,332 rows). Identified from contents (row counts, class mix); the filenames match the contents. Both have 45 columns.
- No existing analysis/notebook/README/results files were seen in the folder, only the two CSVs (plus my own `_action_log.txt`).
- Environment: see `results.json` -> `env` (Python from C:\unsw-runs\env, pandas, numpy, scipy, matplotlib; exact versions recorded there). Code: `analysis.py`. Run: `python analysis.py`.
- Note: the action log lists the commands I ran, but I did not log the listing command's output.

## Data checks
- No missing values and no negative values in the analysed columns.
- Malicious share (label=1): train 119,341/175,341 (68.1%); test 45,332/82,332 (55.1%). Class mix differs between partitions.
- Duplicates (excluding `id`): 67,601 train rows and 26,387 test rows are duplicate feature rows. I kept them, since they are real flow records and the dataset is conventionally used as is; this means effective sample sizes are smaller than nominal. 1,302 distinct feature rows appear in both partitions, so they are not fully independent.
- `id` is a row counter that restarts in each file (82,332 values overlap); I did not use it.
- Structural zeros: 65.0% (train) and 65.8% (test) of malicious flows have dbytes=0, versus 11.9% and 16.7% of normal flows. This is a key feature of the contrast.

## Methods and why
The variables are extremely right-skewed with many zeros and ties, so I used rank-based, distribution-free methods instead of t-tests on means: medians (with a 500-resample bootstrap 95% CI for the median difference), the Mann-Whitney U test, and an effect size, the rank-biserial correlation r = 2*P(malicious > normal) - 1 (negative means malicious values tend to be smaller). With n in the tens of thousands every p-value is effectively 0 (printed as 0.0), so I rely on effect sizes rather than p-values. Consistency (RQ2) was judged by comparing direction and size of r across partitions, and by comparing the same class across partitions. No formal significance test of "difference in r between partitions" was done; I use descriptive judgement. Bootstrap CIs are degenerate for discrete medians (e.g. [-10,-10]) and should not be over-read.

## RQ1: normal vs malicious (medians; r = rank-biserial)
| variable | train normal / malicious median | train r | test normal / malicious median | test r |
|---|---|---|---|---|
| dur | 0.0386 / 0.000009 | -0.28 | 0.223 / 0.00001 | -0.35 |
| sbytes | 1470 / 200 | -0.41 | 974 / 200 | -0.40 |
| dbytes | 1112 / 0 | -0.57 | 354 / 0 | -0.47 |
| spkts | 12 / 2 | -0.41 | 10 / 2 | -0.39 |
| dpkts | 10 / 0 | -0.57 | 8 / 0 | -0.48 |

All five characteristics are typically smaller for malicious traffic: shorter, fewer packets, fewer bytes, and often with no response from the destination. The differences are strongest for destination-side quantities (dbytes, dpkts), moderate for source-side ones and weakest for duration. These are moderate, not extreme, effects; the distributions overlap substantially (P(malicious > normal) is about 0.21-0.36 in train).

Heterogeneity: "malicious" is a mixture. Per category (`cat_summary.txt`, `results.json`), Generic, Backdoor, Analysis and DoS are strongly lower than normal (r down to about -0.87), but Exploits, Fuzzers and Worms are close to normal or even higher for duration (r roughly +0.13 to +0.41 in train). The pooled result is driven by the large Generic class (40,000 train rows) and by the category mix; it does not describe every attack type. Worms has only 130/44 rows, so its estimates are noisy.

## RQ2: consistency across partitions
- Direction: identical in both partitions for all 5 variables (all r negative).
- Magnitude: close for sbytes (-0.41 vs -0.40) and spkts (-0.41 vs -0.39); moderately different for dur (-0.28 vs -0.35), dbytes (-0.57 vs -0.47) and dpkts (-0.57 vs -0.48), where the contrast is weaker in the test set by about 0.09-0.10.
- Source of the differences: malicious traffic is nearly identical across partitions (medians equal or nearly equal; P(test > train) about 0.49-0.50), whereas normal traffic shifts (e.g. median dbytes 1112 -> 354, dur 0.039 -> 0.223 s, P(test > train) for dbytes 0.42). So the changes in effect size come mainly from the normal class differing between partitions.
- By attack category, 41 of 45 category-by-variable effects have the same sign in both partitions. The flips are Exploits on sbytes, dbytes and spkts (small effects near zero, e.g. -0.26 to +0.02 for dbytes) and Worms on spkts (-0.06 to +0.02); all lie near zero, so they are weak-effect instability rather than reversals.

Conclusion: the qualitative pattern (malicious flows smaller/shorter, with no destination response more often) holds consistently in both partitions; effect sizes are similar but not identical, with dbytes, dpkts and dur showing moderate partition differences.

## Caveats
- Association only: this describes flows in a synthetic, lab-generated dataset, not real-world traffic, and says nothing on causation or detection performance.
- The official split is not an independent replication: same capture, overlapping rows (1,302), many duplicates, and different class mix; consistency here is therefore likely optimistic.
- Pooled results depend on the attack mix; only five variables were studied, and several are strongly correlated (bytes/packets), so they are not five independent findings.
- Duplicates were retained; no outlier removal or transformation was applied to the statistics (the boxplots use log scale for display only and hide outliers).
- Category-level per-partition rank-biserial values are not accompanied by CIs.

## Files created
- `analysis.py`, `results.json`, `effects_table.csv`, `consistency_table.csv`, `cat_summary.txt`
- `fig_boxplots_by_partition.png`, `fig_effect_consistency.png`
- `report.md`, `_action_log.txt`
