<!-- Verbatim final message returned by the run 2 agent. Not edited. -->

I've written the report answering both questions. All numbers come from code I ran in this session.

**RQ1 (normal vs malicious).** All five characteristics tend to be smaller for malicious traffic: shorter duration, fewer packets, fewer bytes. About 65% of malicious flows have no destination bytes, against 12–17% of normal flows. The effects are moderate, not extreme:
- **Destination side:** the strongest. Rank-biserial effect size is about -0.47 to -0.57 for `dbytes` and `dpkts`. Negative means malicious values are smaller.
- **Source side:** about -0.40 for `sbytes` and `spkts`.
- **Duration:** the weakest, -0.28 in training and -0.35 in testing.
- **Attack mix:** "malicious" is a mixture. Generic, Backdoor, Analysis and DoS traffic is clearly smaller than normal. Exploits, Fuzzers and Worms are close to normal, and sometimes longer.

**RQ2 (consistency).** The direction is the same in the training and testing partitions for all five variables. Effect sizes for `sbytes` and `spkts` are nearly identical. For `dbytes`, `dpkts` and `dur`, the contrast differs between partitions by about 0.07–0.10. This comes mainly from normal traffic shifting between the files: median `dbytes` falls from 1112 to 354. Malicious traffic barely changes. By attack category, 41 of 45 category-by-variable effects keep the same sign, and the four flips are all near zero.

**Caveats.**
- The two files are not independent. They share 1,302 identical feature rows, and about a third of rows in each file are duplicates, which I kept.
- The malicious share differs: 68% in training and 55% in testing.
- The data is synthetic lab traffic, and the analysis shows association only.
- I used rank-based methods because the variables are heavily skewed. P-values are effectively zero at this sample size, so I relied on effect sizes.
- I did not formally test whether effect sizes differ between partitions.

I saw no existing analysis, notebook, README or results files in the folder, only the two CSVs. The software versions used are recorded in `results.json`.

Files created (all in `C:\unsw-runs\run2`):
- `analysis.py`
- `results.json`
- `effects_table.csv`
- `consistency_table.csv`
- `cat_summary.txt`
- `fig_boxplots_by_partition.png`
- `fig_effect_consistency.png`
- `report.md`
- `_action_log.txt`
