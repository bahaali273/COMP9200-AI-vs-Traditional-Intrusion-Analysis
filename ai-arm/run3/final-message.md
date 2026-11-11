<!-- Verbatim final message returned by the run 3 agent. Not edited. -->

Malicious flows are typically shorter and smaller than normal ones, and that holds in both the training and testing partitions. I ran `analysis.py`, and every number in `report.md` comes from that run.

**RQ1.** For all five variables (`dur`, `sbytes`, `dbytes`, `spkts`, `dpkts`), the typical malicious flow is shorter, smaller and has fewer packets. The gap is largest on the destination side: the median malicious flow has 0 `dbytes` and 0 `dpkts`. This is a statement about typical flows, not all of them. A few very large malicious flows pull the mean `sbytes` above normal even though the median is lower.

**RQ2.** The direction is the same in both partitions for all five variables, and the effect sizes are broadly similar. They differ most for `dbytes`, `dpkts` and `dur`, by about 0.07 to 0.10 in Cliff's delta (a rank-based effect size). Malicious traffic looks almost the same across the two partitions. Most of the shift comes from the normal traffic, which differs in the testing set. Some attack categories, notably Exploits, change a lot between partitions, but none flips sign where the effect is clear in both.

**Caveats:**
- **Duplicates:** There are many exact duplicate rows (67,601 in train, 26,387 in test). I kept them, so the p-values and confidence intervals overstate how independent the data are.
- **Partitions:** The two files are the official split, not random halves of one sample, and their class mix differs (68% malicious in train, 55% in test). Agreement between them does not show the findings hold on other networks.

I saw no existing analysis, notebook, README or results file in the folder, only the two CSVs and `_action_log.txt`. I identified the training file by its row count (175,341 rows, versus 82,332 for testing).

Files created in `C:\unsw-runs\run3`:
- `analysis.py`
- `analysis_output.txt`
- `results_meta.json`
- `rq1_summary.csv`
- `rq1_cliff_bootstrap_ci.csv`
- `rq1_by_attack_cat.csv`
- `rq2_consistency.csv`
- `rq2_class_shift.csv`
- `rq2_attack_cat_consistency.csv`
- `fig_boxplots.png`
- `fig_effect_sizes.png`
- `report.md`

I also appended to the operator-provided `_action_log.txt`. It lists only two commands: the folder listing and the `analysis.py` run. The file-creation steps were not shell commands.
