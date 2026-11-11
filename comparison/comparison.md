# AI-Assisted vs Python Analysis: Evidence for the Comparison (RQ3)

Sources:

- **Python arm:** `notebooks/01_dataset_exploration.ipynb` (recorded outputs).
- **AI arm:** `ai-arm/run1` to `run3` (outputs and verbatim final messages).
- **Checks:** `ai-arm/verification/` (scripts and results written by the operator).

Every number below was read from those files or recomputed by the verification
scripts. The evidence is organised by the five criteria in Assignment 3, Part 1c.
This document records evidence only. Any scoring or judgement is left to the authors.

## 1. Findings: what each arm concluded

| Item | Python arm | AI arm (runs 1 to 3) | Agreement |
|---|---|---|---|
| Rows train / test | 175,341 / 82,332 | same, all runs | identical |
| Malicious share, train | 68.06% | 68.1%, all runs | identical |
| Malicious share, test | not reported | 55.1% (runs 2, 3); run 1 reports a normal share of 44.9% | AI only |
| Missing values | 0 | 0 | identical |
| Duplicates, excluding id | 67,601 / 26,387 | runs 2, 3: 67,601 / 26,387; run 1: "no duplicate rows" (wrong: its check included the unique id column) | 2 of 3 runs match |
| sbytes median, normal vs malicious | 1470 vs 200 (train), 974 vs 200 (test) | same | identical |
| Medians for the other four features | train only | train and test | identical where both exist |
| sbytes rank-biserial r | -0.4134 (train), -0.3988 (test) | -0.4134 / -0.3988, all runs (run 1 and run 3 call it Cliff's delta) | identical |
| sbytes U statistic | 1,960,253,092.5 (train) | not reported | recomputed by the operator: identical |
| Effect sizes for dur, dbytes, spkts, dpkts | not computed | computed, identical in all 3 runs | AI only |
| Attack-category medians (sbytes, dur, spkts) | train only | train and test | identical where both exist |
| Category effect sizes vs normal | not computed | 45 category x feature cells per partition | AI only |
| Direction consistent across partitions | sbytes only, yes | all 5 features, yes | agree |
| Partition shift in normal traffic | not examined | normal-class KS 0.12 to 0.18; malicious-class KS at most 0.075 (runs 1, 3) | AI only |
| Rows shared between partitions | not examined | 1,302 distinct feature rows (run 2) | AI only |

**Main result.** Wherever both arms computed the same quantity, the numbers agree
exactly. All three runs chose the same test and the same effect size as the Python
arm (Mann-Whitney U with rank-biserial, sign convention malicious vs normal),
without being told which to use. The AI arm covered more: five inferential
features instead of one, both partitions throughout, the attack categories
compared against normal traffic, and diagnostics of the shift between partitions.

## 2. Rigor

| Aspect | Python arm | AI arm |
|---|---|---|
| Test choice | Mann-Whitney U, method stated as asymptotic | Mann-Whitney U, default method; skew and zero inflation given as the reason |
| Use of p-values | Binary "Reject H0 at alpha = 0.05" decision; p printed as 0.000000e+00 and reported as p < 0.001 | All runs say p-values are uninformative at this n and rely on effect sizes instead |
| Effect-size interpretation | Direction only | Run 3 gives thresholds (0.15, 0.33 and 0.47 for small, medium and large) as conventions, without a citation; runs 1 and 2 call the effects "moderate" |
| Uncertainty | None | Run 3: bootstrap CIs for delta (200 resamples of 3,000 per class). Run 2: bootstrap CI for the median difference, which it notes is degenerate |
| Multiple comparisons | One test per partition | About 100 tests; no correction, which runs 1 and 3 justify because they rely on effect sizes |
| Dependence and duplicates | Kept; noted as a limitation | Kept in runs 2 and 3, with the consequence explained, and the duplicate check excluded `id`. Run 1's one-off check included the unique `id`, so it could never find duplicates. Run 2's transcript shows it reasoned that `id` is only a row counter |
| Confounding by attack mix | Notes that categories differ | Runs 1 and 2 claim the pooled effect is "driven by" Generic but do not test it. The operator check (`generic_sensitivity.csv`) supports the claim: without Generic, the dur effect drops from -0.285 to -0.007 |
| Class-mix difference as a confound for RQ2 | Not examined | Noted (68% vs 55% malicious). Neither arm quantified the shift in Generic share (33.5% of malicious in train, 41.6% in test) |

## 3. Transparency

| Aspect | Python arm | AI arm |
|---|---|---|
| Code available | Notebook with outputs | `analysis.py` per run |
| Claims traceable to code | Yes, by cell | Yes, through the transcripts. Run 3 cites a file for each claim. One wrong claim (run 1, duplicates, from a flawed check) and some untested interpretations |
| Invented or unsupported numbers | None found | None invented: 20 of 21 audited claims correct; the 1 wrong value was actually computed, by a flawed method (`claim_audit.csv`) |
| Process record | Full notebook | Platform transcripts with every tool call, its arguments and its result (`ai-arm/runN/transcript/`). Some reasoning summaries are redacted; the self-reported action logs are incomplete |
| Tool and model identification | Python, Colab, versions (matplotlib missing) | Agentic AI coding assistant, Claude model family; the model version is unknown because selection was automatic, not pinned |
| Steps outside the saved script | None | Run 1: a one-off inspection command (the source of the duplicate error). Run 2: a command that built `cat_summary.txt` from `results.json`. Both are recorded in the transcripts but not in `analysis.py` |
| Context not in the prompt | n/a | The platform added a user-level instruction file about maths formatting (`latex-in-markdown.md`) to every run |
| Code provenance | Written with ChatGPT help, then run and checked by humans | Written and run autonomously by the AI |

## 4. Bias

| Aspect | Python arm | AI arm |
|---|---|---|
| Causal language | None | None; uses "association only" explicitly (runs 1 to 3) |
| Speculative explanations | None | Some, often hedged: "probably reflecting timestamp resolution" (run 1); "repeated scans/DoS from the same sources" (run 3); "often get little or no response" (runs 2, 3) |
| Framing of the test partition | Called "Independent Testing Dataset Validation" | Runs 2 and 3 say the partitions are not independent (shared rows, the same capture) |
| Generalisation | Limitation noted | Limitation noted in all runs |
| Conflicting interpretations between runs | n/a | Run 1 calls the official split "a fairly strict test" of consistency; run 2 says the consistency is "likely optimistic" |
| Confirmation risk | Assertions hard-code the expected direction (`assert rank_biserial < 0`) | Defines its consistency criteria after computing them, not in advance |

## 5. Reproducibility

| Aspect | Python arm | AI arm |
|---|---|---|
| Rerun from code | Not rerun by the operator in Colab. Key values recomputed locally match (U, r, medians) | All saved outputs reproduced byte-for-byte from `analysis.py`, all 3 runs |
| Across library versions | scipy 1.16.3 (Colab) vs 1.15.3 (local): identical U and r | n/a, one environment |
| Run-to-run agreement on numbers | n/a | Identical where methods overlap (maximum difference 5.6e-17) |
| Run-to-run agreement on scope | n/a | Differs: run 3 adds bootstrap CIs and a class-shift table; run 2 adds the row-overlap check and a median-difference CI; run 1 omits the duplicate check |
| Run-to-run agreement on interpretation | n/a | Same answers to RQ1 and RQ2; different framing of what partition consistency means |
| Environment dependence | Google Drive path must be edited | Absolute interpreter path; data must be in the working folder |

## Threats to validity of this comparison

1. **The baseline is also AI-assisted.** ChatGPT helped write the Python arm. The
   comparison is between a human-verified notebook and autonomous agent output,
   not between human and AI analysis.
2. **The model was not pinned.** It is unknown whether the three runs used the
   same model.
3. **Low independence.** The near-identical code across runs (identical figure
   files in runs 1 and 3) means 3 runs say less about variability than 3
   independent analysts would.
4. **Partial reasoning record.** The transcripts were recovered from the session
   store after the runs. They record every action, but some reasoning summaries
   are redacted, so why the agent made a choice can't always be seen.
5. **The task prompt named the five features and both labels.** This limited the
   room for the AI to choose different variables.
6. **The operator ran the claim audit and knew the baseline values.** Scoring
   should be done by group members, ideally blind to which run is which.
7. **Sample of claims.** 21 claims were audited, not every number in the reports.
