# COMP 9200: AI-Assisted vs. Independent Network Intrusion Analysis

**Course:** COMP 9200, Applied Research Methods, BCIT, Assignment 3 Part 1 (pairs)
**Dataset:** UNSW-NB15, official training and testing partitions

**Status:**

| Part | State |
|---|---|
| Python arm (baseline) | Complete |
| AI arm | Complete: 3 runs, 2026-11-09 |
| Verification | Complete |
| IEEE paper | Not yet written; this is the authors' job |

This README is the hand-off for writing the paper. It records:

- what was done, and every design decision with its reason;
- every result, with the file it comes from;
- what the paper must disclose;
- what is still open.

All numbers below were computed by code and can be traced to the files named.

---

## 1. Research questions

1. **RQ1:** How do selected network traffic characteristics differ between normal and malicious traffic?
2. **RQ2:** Do the observed differences remain consistent across the training and testing partitions?
3. **RQ3:** How do generative AI-assisted findings compare with the Python-based analysis in accuracy of interpretation, rigor, transparency, bias and reproducibility?

RQ1 and RQ2 are answered by both arms. RQ3 is the methodological question the
paper is about: it compares the two arms.

The study is **descriptive and comparative, not predictive**. No classifier was
trained. The findings are not evidence of causation or of detection accuracy.

## 2. What is where

```text
COMP9200-AI-vs-Traditional-Intrusion-Analysis/
├── README.md                     <- this hand-off
├── notebooks/
│   └── 01_dataset_exploration.ipynb   Python arm (baseline), with recorded outputs
├── protocol/
│   ├── system-prompt.md          open-ended task prompt given to the AI
│   └── agent-wrapper-prompt.txt  wrapper + task, exactly as pasted
├── ai-arm/                       AI arm: full prompt/output disclosure
│   ├── README.md                 setup, hashes, verification, limitations
│   ├── runN/prompt-sent.txt      exact prompt each run received
│   ├── runN/transcript/          platform transcript (raw JSONL + readable .md)
│   ├── runN/final-message.md     agent's final message, verbatim
│   ├── runN/outputs/             every file the agent created (code, CSV/JSON, figures, report.md)
│   └── verification/             operator scripts + results (not part of the AI arm)
└── comparison/
    └── comparison.md             evidence table for each RQ3 criterion
```

The dataset CSVs are not stored in the repository; see Section 12.

---

## 3. Dataset and data integrity

| File | Rows | Columns | SHA256 |
|---|---:|---:|---|
| UNSW_NB15_training-set.csv | 175,341 | 45 | BEC7DD5EC88DC2A0CCC7A07879D338395ED7421750F675FD0339E07DFE0648FA |
| UNSW_NB15_testing-set.csv | 82,332 | 45 | 734FE6642EDF758F7C94D7D9149426B49D202FE8E7BF0BEF47392489C3C0A559 |

- **Source:** https://research.unsw.edu.au/projects/unsw-nb15-dataset. The files
  were placed in `group/data/` by the team. Their row counts match the published
  counts. The hashes were not checked against an official checksum, because
  UNSW does not publish one.
- **Same data in every run:** the hashes were identical in every AI-arm folder,
  both before and after each run.
- **Variables:**
  - five features: `dur` (duration), `sbytes` and `dbytes` (source and
    destination bytes), `spkts` and `dpkts` (source and destination packets);
  - `label`: 0 = normal, 1 = malicious;
  - `attack_cat`: 9 attack categories plus Normal.
- **Licence:** free for academic research. The authors ask that the UNSW-NB15
  papers be cited (Section 11).

---

## 4. Design decisions (decision log)

Use these for the Methodology section and to answer "why did you do X?"

| # | Decision | Reason |
|---|---|---|
| D1 | Descriptive study, not a classifier | Matches RQ1 and RQ2. The README and notebook already framed findings as "not evidence of detection accuracy". |
| D2 | Official train/test partitions, not the 2.5M-row raw files | RQ2 asks about the two partitions, and the AI arm must use the same data as the Python arm for a fair comparison. |
| D3 | The same five features in both arms | Keeps the arms comparable on RQ1. Trade-off: it limits the AI's freedom to choose variables (a threat to validity). |
| D4 | **Open-ended** AI prompt: research questions, data and rules only, with no methods named | RQ3 asks about the AI's rigor and bias. Naming the tests would only measure whether it can follow instructions. A guided prompt was drafted and rejected for this reason. |
| D5 | One long prompt, completed autonomously in one session, with no follow-up prompts | Removes human steering from the AI arm. The agent was told not to ask questions. |
| D6 | **3 runs**, each in a fresh context | One run cannot show reproducibility, which is an RQ3 criterion. Three is enough to see agreement or disagreement and still manageable to score. |
| D7 | One tool for all runs: an agentic AI coding assistant, Claude model family (Anthropic) | Mixing tools would confound the comparison. Using a different vendor from the baseline (ChatGPT) keeps the two arms' AI sources separate. |
| D8 | Framing: "human-verified, rerunnable notebook vs autonomous AI agent", **not** "human vs AI" | The Python arm was itself written with ChatGPT's help, so "independent" or "traditional" would overstate the contrast. State this openly. |
| D9 | Isolation: each run in an empty folder outside the repo, containing only the two CSVs; the prompt forbids other files and internet | Stops the AI from seeing the baseline's results. Confirmed afterwards from the transcripts (Section 7). |
| D10 | The prompt does not contain any baseline result | Avoids anchoring the AI. The only dataset facts given were the column names and their meanings. |
| D11 | Operating wrapper around the task prompt: one-shot, no questions, stay in folder, stop rather than invent numbers if code can't run, write `report.md` | Mechanics only, with no method guidance. The wrapper is part of the AI condition and must be reported. |
| D12 | Pre-installed, pinned Python environment (pandas 2.2.3, numpy 2.2.6, scipy 1.15.3, matplotlib 3.10.3, seaborn 0.13.2) | Prevents three parallel agents from installing packages at the same time and fixes the library versions. Trade-off: the AI did not choose its environment. |
| D13 | Runs launched as sub-agents of an operator session, not as three separate interactive sessions | Practical constraint at the time. Consequences: the model was not pinned, and the transcripts had to be recovered from the assistant's local session store (Section 9, item 8). |
| D14 | An operator note was added to each prompt: folder path, interpreter path, and a request to log commands | Needed because sub-agents don't start in the run folder. It is the only part of the prompt that differs between runs (the folder number). |
| D15 | Duplicates retained (both arms) | Identical flow records are not necessarily errors. The consequence (dependent observations) is reported. |
| D16 | Operator verification after the runs: rerun, cross-run comparison, claim audit, and one extra test | Without independent checking, "AI accuracy" cannot be judged. |

---

## 5. Procedure (what actually happened)

1. **Prompt design.** The prompt was designed and fixed in `protocol/system-prompt.md`.
2. **Wrapper.** The wrapper was added to make `protocol/agent-wrapper-prompt.txt`
   (SHA256 8932CB4996D1A987A6C8085F105BA621B87A651EBED3B3671B18F3023EE639B4).
3. **Run folders.** Three folders were created (`C:\unsw-runs\run1` to `run3`),
   each containing only the two CSVs, and their hashes were checked.
4. **Runs.** The three runs were launched in parallel on 2026-11-09. Times are in
   British Columbia time; the transcripts use UTC.

   | Run | Started | Tool calls | Last output written |
   |---|---|---:|---|
   | 1 | 14:31:55 | 6 | 14:32:44 |
   | 2 | 14:32:04 | 5 | 14:32:56 |
   | 3 | 14:32:12 | 4 | 14:33:00 |

   Each run took about one minute. There was no human interaction during the runs.
5. **Post-run checks.** The data hashes were re-checked, the outputs collected,
   and the transcripts copied from the assistant's local session store and redacted (see `ai-arm/README.md`).
6. **Verification.** The operator ran the checks described in Section 7.

The pilot run that had been planned was **not** done. The prompt was frozen
without one.

---

## 6. Results

### 6.1 Python arm (baseline): `notebooks/01_dataset_exploration.ipynb`

- **Environment:** Colab, pandas 2.2.3, NumPy 2.4.6, SciPy 1.16.3. The
  matplotlib version was not recorded and is still open.
- **Class balance:** 68.06% malicious in train (119,341 of 175,341). The test
  split was not reported in the notebook's class table.
- **Data quality:** 0 missing values. Excluding `id`, there are 67,601 duplicate
  rows in train and 26,387 in test.
- **Medians:** all 5 features, normal vs malicious, **training set only**.
- **Inference:** Mann-Whitney U on **`sbytes` only**:

  | | U | p | r |
  |---|---|---|---|
  | Train | 1,960,253,092.5 | prints as 0 | **-0.4134** |
  | Test | 504,205,113.0 | prints as 0 | **-0.3988** |

  The p-value underflows to zero, so the notebook reports it as "p < 0.001".
  The decision was framed as "Reject H0, alpha = 0.05".
- **Attack categories:** median `sbytes`, `dur` and `spkts` per category,
  training set only. There was no comparison with normal traffic.
- **Assertions:** they check the expected direction (`rank_biserial < 0`).

### 6.2 AI arm: RQ1 (identical in all 3 runs)

All three runs **independently chose** the Mann-Whitney U test with
rank-biserial r, using the same sign convention as the baseline: negative means
malicious values tend to be lower. Runs 1 and 3 call it "Cliff's delta"; it is
the same quantity.

The values below come from `ai-arm/verification/cross_run_headline.csv`.

| Feature | Train median N / M | Train r | Test median N / M | Test r |
|---|---|---:|---|---:|
| dur | 0.0386 / 0.000009 | -0.285 | 0.2228 / 0.00001 | -0.354 |
| sbytes | 1470 / 200 | -0.413 | 974 / 200 | -0.399 |
| dbytes | 1112 / 0 | -0.573 | 354 / 0 | -0.473 |
| spkts | 12 / 2 | -0.412 | 10 / 2 | -0.392 |
| dpkts | 10 / 0 | -0.566 | 8 / 0 | -0.475 |

N = normal (n = 56,000 train, 37,000 test). M = malicious (n = 119,341 train,
45,332 test).

**Main RQ1 points:**

- The typical malicious flow is shorter and smaller, with fewer packets in both
  directions.
- The effects are moderate (|r| between 0.28 and 0.57), so the distributions
  overlap heavily.
- The destination side differs most:

  | Flows with `dbytes` = 0 | Train | Test |
  |---|---|---|
  | Malicious | 65.0% | 65.8% |
  | Normal | 11.9% | 16.7% |

- Means point the other way from medians for `sbytes`. Mean malicious vs normal
  is 11,069 vs 4,106 in train and 11,195 vs 4,072 in test, because a few very
  large malicious flows pull the mean up.
- The pattern is not uniform across attack categories:
  - Generic is far below normal on every feature (r from -0.70 to -0.87, train).
  - Exploits, Fuzzers and Worms are close to normal or longer on `dur`
    (Exploits +0.128, Worms +0.406, train).
  - Small categories have few rows, so their estimates are noisy (Worms has 130
    rows in train and 44 in test).

### 6.3 AI arm: RQ2

- **Direction:** the same in both partitions for all 5 features.
- **Size:** the difference in r between train and test is 0.070 (dur), 0.015
  (sbytes), 0.101 (dbytes), 0.020 (spkts) and 0.091 (dpkts).
- **What changes is normal traffic.** Kolmogorov-Smirnov statistics for train vs
  test, within each class:

  | Class | KS range |
  |---|---|
  | Normal | 0.122 to 0.177 |
  | Malicious | 0.010 to 0.075 |

  Example: median normal `dbytes` is 1112 in train and 354 in test.
- **Class mix differs:** 68.1% malicious in train and 55.1% in test.
- **The partitions are not independent:** they share 1,302 distinct feature rows
  (found by run 2). Do **not** call the test set "independent validation", as the
  notebook does.
- **Attack categories:** 41 of 45 category-by-feature effects keep their sign
  across partitions. The 4 that flip (Exploits on `sbytes`, `dbytes` and `spkts`;
  Worms on `spkts`) are all near zero.
- **Category effects are less stable than pooled ones.** Example: Analysis on
  `dur` is -0.352 in train and -0.683 in test.

### 6.4 Extra operator check: the Generic composition effect

Runs 1 and 2 said the pooled effect is "driven by" the Generic category, but did
not test it. The operator tested it (`ai-arm/verification/generic_sensitivity.csv`).

| Feature | r, all malicious (train / test) | r, without Generic (train / test) |
|---|---|---|
| dur | -0.285 / -0.354 | **-0.007 / -0.047** |
| sbytes | -0.413 / -0.399 | -0.206 / -0.144 |
| dbytes | -0.573 / -0.473 | -0.426 / -0.243 |
| spkts | -0.412 / -0.392 | -0.267 / -0.168 |
| dpkts | -0.566 / -0.475 | -0.413 / -0.245 |

- The AI's claim is supported. The duration difference almost disappears
  without Generic attacks.
- Generic makes up 33.5% of malicious traffic in train and 41.6% in test.
  **Neither arm** identified this composition shift as a confound for RQ2.
  Say this in the paper.

---

## 7. Verification (operator, after the runs)

These results are in `ai-arm/verification/`. They are not part of the AI arm.

| Check | Result |
|---|---|
| **Rerun** each `analysis.py` from a clean copy of the data | All saved CSV, JSON and PNG outputs reproduced **byte-for-byte**, in all 3 runs |
| **Cross-run agreement** | Identical r in all 3 runs for every feature and partition (largest difference 5.6e-17) |
| **Agreement with the baseline** | sbytes r -0.4134 / -0.3988 identical. The baseline U statistic reproduced exactly with SciPy 1.15.3 (the baseline used 1.16.3). Medians and category medians identical. Duplicate counts match in runs 2 and 3. |
| **Claim audit**: 21 numeric claims sampled from the 3 reports and recomputed from raw data | **20 correct, 1 wrong** (see below) |
| **Isolation** | Every path touched by every tool call in the transcripts is inside the run's own folder or the shared Python interpreter. No run accessed the repo, the notebook or another run. |

**The one wrong claim.** Run 1 reports "no duplicate rows". The transcript shows
why: its quick check was `d.duplicated().sum()` on the whole table, **including
the unique `id` column**, so it could never find any. Excluding `id`, there are
67,601 duplicate rows in train and 26,387 in test. Run 2 excluded `id` and
recorded why.

Describe this as a **method error presented confidently**, not as a hallucination
or an invented number. The number was computed; the check was flawed.

---

## 8. RQ3 evidence summary

Full tables are in `comparison/comparison.md`. Scoring and judgement belong to
the authors.

| Criterion | Python arm | AI arm |
|---|---|---|
| Findings | 1 feature tested; categories train-only | 5 features, both partitions, categories vs normal, shift diagnostics. Same numbers wherever both computed. |
| Accuracy | No errors found | 20 of 21 audited claims correct; 1 wrong value from a flawed check. Untested interpretations (one checked and supported). |
| Rigor | Binary p-value decision with an underflowed p; dependence noted | Said p-values are uninformative at this n and used effect sizes. Run 3 added bootstrap CIs and effect-size thresholds (uncited). About 100 tests, no multiplicity correction (justified). |
| Transparency | Full notebook | Code, outputs and platform transcripts. Some reasoning redacted. Model unknown. Two results came from one-off commands outside the saved script (visible in the transcripts). |
| Bias | No causal language. Calls the test set "independent validation". Assertions encode the expected direction. | No causal language. Hedged speculation ("probably reflecting timestamp resolution"). **Runs disagree on framing:** run 1 calls the partition check "a fairly strict test", run 2 says "likely optimistic". |
| Reproducibility | Values reproduce across SciPy versions | Byte-identical reruns; identical numbers across runs. Scope differed between runs; for example, run 1 skipped the proper duplicate check. |

**Main message, supported by the evidence:** the AI arm matched the numbers
exactly and chose the same methods without being told to. Its weaknesses were in
**accountability**:

- a confidently stated wrong value from a flawed check;
- interpretations left untested;
- a process record that had to be recovered after the fact.

---

## 9. Limitations 

1. **The baseline is AI-assisted too.** ChatGPT helped write it. See D8.
2. **The model was not pinned.** The session used "Auto", so it is unknown
   whether all 3 runs used the same model. Differences between runs can't be
   attributed to sampling alone.
3. **The runs are not independent.** The three scripts are near-identical (same
   plotting code; runs 1 and 3 produced byte-identical figures). This reflects
   one model's habits, not three independent analysts.
4. **Only 3 runs.** They show agreement or disagreement, but cannot estimate how
   variable the AI is.
5. **Context outside the prompt.**
   - The platform automatically added a user-level instruction file
     (`latex-in-markdown.md`, rules for formatting maths in chat)
     to every run. It contains no analysis guidance.
   - The operator note and the wrapper are part of the AI condition.
6. **The environment was pre-installed** by the operator (D12).
7. **The prompt named the five features and both labels** (D3).
8. **Transcripts were recovered from the local session store after the runs.**
   This is not a documented export. Some reasoning summaries are redacted. The
   opening prompt is not in the log; it is stored separately as
   `prompt-sent.txt`. The agents' own action logs are incomplete; rely on the
   transcripts.
9. **The operator knew the baseline values when auditing.** Only 21 claims were
   sampled, not every number.
10. **No pilot run** was done before freezing the prompt.
11. **Statistics.**
    - Duplicates and dependent flows were kept, so p-values and CIs treat the
      data as more independent than it is.
    - At n of tens of thousands, every p-value underflows to 0.
    - Report effect sizes as descriptive.
12. **External validity.** UNSW-NB15 is synthetic testbed traffic from 2015, so
    findings may not generalise to real networks. Only one tool and one task
    were tested.

---

## 10. Guidance for writing the paper

The assignment requires a **4 to 6 page IEEE LaTeX conference paper**. Use the
course template, not this repo. The required sections and their sources:

| Paper section | Sources in this README |
|---|---|
| Abstract, Introduction | Sections 1 and 8 (main message) |
| Related Work (brief) | Section 11. **AI-analysis sources still need to be found.** |
| Methodology: dataset, preprocessing | Sections 3 and 4 (D1 to D3, D15) |
| Methodology: AI tool setup | Sections 4 (D4 to D14) and 5, plus `ai-arm/README.md` |
| Methodology: your pipeline | Section 6.1 and the notebook |
| Results: AI vs you | Sections 6, 7 and 8 |
| Discussion: interpretation, validity, ethics, reproducibility, AI transparency | Sections 8 and 9 |
| Conclusion | Section 8 |
| AI use statement | Section 13 |

**Wording to get right:**

- Say "rank-biserial correlation r", and note that it equals Cliff's delta.
  Negative means malicious values are lower.
- Say "p < 0.001" or "p underflows to 0". Don't print "p = 0".
- Say "associated with" and "differs". Never "causes".
- Don't call the test partition "independent".
- Call run 1's duplicate claim a "flawed check", not a "hallucination".
- Call the AI arm an "autonomous agentic coding assistant". It is not a chat
  window.
- Report the AI tool as "an agentic AI coding assistant, Claude model family
  (Anthropic), model not pinned". If the instructor asks which product it was,
  answer honestly. The team holds the unredacted originals.

**Full prompt and output disclosure** is required by the assignment. Point to
`ai-arm/` in the paper, or include it as supplementary material.

**Decisions only the authors can make:**

- Who scores the RQ3 criteria, and whether scoring is blind to run identity.
  Ideally both authors score `comparison/comparison.md` independently and you
  report agreement.
- Whether to rerun the AI arm with a pinned model in fresh interactive sessions,
  exporting each transcript. That would remove limitations 2 and 8. The
  verification scripts can be reused.

**A suggested figure** (not produced in the repo): grouped bars of r by feature
and partition, with markers for "without Generic" and the baseline sbytes
values. Data: `cross_run_headline.csv` and `generic_sensitivity.csv`.

---

## 11. References identified so far

**Verify every entry in Zotero before citing.** Check the authors, pages and DOI.

| Use | Reference |
|---|---|
| Dataset (required by the licence) | N. Moustafa and J. Slay, "UNSW-NB15: A comprehensive data set for network intrusion detection systems (UNSW-NB15 network data set)," MilCIS 2015, doi:10.1109/MilCIS.2015.7348942 |
| Dataset statistics | N. Moustafa and J. Slay, "The evaluation of network anomaly detection systems: Statistical analysis of the UNSW-NB15 data set and the comparison with the KDD99 data set," *Information Security Journal: A Global Perspective*, 25(1–3), 18–31, 2016, doi:10.1080/19393555.2015.1125974 |
| Dataset page | UNSW-NB15 dataset page, https://research.unsw.edu.au/projects/unsw-nb15-dataset. The page asks users to cite five papers; check which ones apply. |
| Mann-Whitney U | H. B. Mann and D. R. Whitney, *Ann. Math. Statist.*, 18(1), 50–60, 1947, doi:10.1214/aoms/1177730491 |
| Rank-biserial r | D. S. Kerby, "The simple difference formula," *Comprehensive Psychology*, 3, 2014, doi:10.2466/11.IT.3.1 |
| Cliff's delta | N. Cliff, "Dominance statistics," *Psychological Bulletin*, 114(3), 494–509, 1993, doi:10.1037/0033-2909.114.3.494 |
| SciPy | P. Virtanen et al., "SciPy 1.0," *Nature Methods*, 17, 261–272, 2020, doi:10.1038/s41592-019-0686-2 |
| **Still needed** | 2 to 4 peer-reviewed sources on LLMs or AI assistants for data analysis, and on the reproducibility or transparency of AI-assisted research |

Run 3 used effect-size thresholds of 0.15, 0.33 and 0.47 (small, medium, large)
without citing a source. If you use those thresholds, find and cite a source.

---

## 12. Reproducing

**Python arm.**

1. Download the two CSVs from the UNSW page.
2. Open `notebooks/01_dataset_exploration.ipynb` in Colab.
3. Set `data_path` to the CSVs' location.
4. Run all cells.

**AI arm outputs.** From each `ai-arm/runN/outputs/` folder, with the two CSVs
copied into it, run:

```text
python analysis.py
```

Use the library versions in D12. The outputs should match byte for byte, except
for the OS build string, which was redacted in three JSON files (see
`ai-arm/README.md`).

**Verification scripts.** Run these from the repository root. The scripts look
for the dataset CSVs in `../data`, next to the repository, or in the folder
named by the `UNSW_DATA` environment variable:

```text
python ai-arm/verification/compare_runs.py
python ai-arm/verification/audit_claims.py
python ai-arm/verification/extra_checks.py
python ai-arm/verification/render_transcripts.py
```

`check-run-folder.ps1 -Folder <path>` checks a run folder's row counts and data
hashes.

---

## 13. AI use disclosure (repository)

- **Python arm.** ChatGPT (OpenAI) helped with the code, statistical
  explanations, interpretation and documentation. A team member ran the notebook
  in Google Colab and inspected the outputs.
- **AI arm.** It was run with an agentic AI coding assistant (Claude model
  family, Anthropic; model not pinned). All prompts, transcripts, final messages
  and outputs are in `ai-arm/`.
- **Operator work.** The same AI coding assistant also:
  - helped design the study protocol and prompts with the team;
  - set up and ran the three AI-arm runs;
  - carried out the verification checks and the redaction;
  - wrote `ai-arm/README.md`, `comparison/comparison.md` and this README.
- **Earlier draft.** The assistant generated a draft IEEE paper, which was
  removed from the repository. The team keeps a copy outside it. If any part of
  that draft is used, disclose it in the paper's AI use statement.
- **Redaction.** Personal and tool-identifying strings were redacted from the
  published files (see `ai-arm/README.md`). The analysis content was not changed.
- **Responsibility.** The authors are responsible for the paper, its analysis
  and its conclusions. They must write their own AI use statement.

## 14. Open items

- [ ] Write the paper (4 to 6 pages, IEEE LaTeX, course template)
- [ ] Find and verify the Related Work sources on AI-assisted analysis
- [ ] Verify all references in Zotero
- [ ] Decide on scoring, and on blinding, for RQ3
- [ ] Record the matplotlib version used in the Colab notebook
- [ ] Optional: rerun the AI arm with a pinned model and exported transcripts
- [ ] Write each author's AI use statement
- [ ] Commit and push (nothing has been committed yet; the CSVs stay out of git)
