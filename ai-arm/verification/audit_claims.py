# Operator tool: independently recompute specific numeric claims made in the three AI reports.
# Not part of the AI arm. Computed directly from the original CSVs.
# Data folder: environment variable UNSW_DATA, default ../data next to the repository.
import os
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import mannwhitneyu

HERE = Path(__file__).resolve().parent
D = Path(os.environ.get("UNSW_DATA", HERE.parents[2] / "data"))
tr = pd.read_csv(D / "UNSW_NB15_training-set.csv")
te = pd.read_csv(D / "UNSW_NB15_testing-set.csv")
P = {"train": tr, "test": te}
F = ["dur", "sbytes", "dbytes", "spkts", "dpkts"]


def rb(x, y):
    """Rank-biserial / Cliff's delta, x vs y (positive => x larger)."""
    return 2 * mannwhitneyu(x, y).statistic / (len(x) * len(y)) - 1


rows = []


def claim(run, text, claimed, actual, ok):
    rows.append(dict(run=run, claim=text, claimed=claimed, recomputed=actual, verdict="OK" if ok else "WRONG"))


# --- data quality claims
dup_tr = int(tr.drop(columns="id").duplicated().sum())
dup_te = int(te.drop(columns="id").duplicated().sum())
claim("run1", "No duplicate rows (its ad-hoc check counted duplicates WITH the unique id column)", "0", f"{dup_tr} train / {dup_te} test (excluding id)", dup_tr == 0)
claim("run2,run3", "Duplicates excl. id 67,601 / 26,387", "67601/26387", f"{dup_tr}/{dup_te}", (dup_tr, dup_te) == (67601, 26387))
miss = int(tr[F].isna().sum().sum() + te[F].isna().sum().sum())
claim("all", "No missing values in five features", "0", str(miss), miss == 0)
mism = int(((tr.attack_cat == "Normal") != (tr.label == 0)).sum() + ((te.attack_cat == "Normal") != (te.label == 0)).sum())
claim("run3", "label and attack_cat agree", "0 mismatches", str(mism), mism == 0)

# --- zero counts
z = {p: int((d.dbytes == 0).sum()) for p, d in P.items()}
claim("run3", "Zero dbytes rows 84,282 / 36,006", "84282/36006", f"{z['train']}/{z['test']}", (z["train"], z["test"]) == (84282, 36006))
zd = {p: int((d.dur == 0).sum()) for p, d in P.items()}
claim("run3", "Zero dur rows 2,657 / 950", "2657/950", f"{zd['train']}/{zd['test']}", (zd["train"], zd["test"]) == (2657, 950))
for p, d in P.items():
    m = d[d.label == 1]
    both = (m.dbytes.eq(0) & m.dpkts.eq(0)).mean() * 100
    only_db = m.dbytes.eq(0).mean() * 100
    claimed = 65.1 if p == "train" else 65.8
    claim("run1", f"{p}: % malicious with dbytes = dpkts = 0", f"{claimed}%", f"{both:.2f}% (dbytes=0 alone {only_db:.2f}%)", abs(both - claimed) < 0.1)

# --- means
for p, d in P.items():
    mm, mn = d.loc[d.label == 1, "sbytes"].mean(), d.loc[d.label == 0, "sbytes"].mean()
    c = "11,069 vs 4,106" if p == "train" else "11,195 vs 4,072"
    claim("run1", f"{p}: mean sbytes malicious vs normal", c, f"{mm:,.0f} vs {mn:,.0f}", c == f"{mm:,.0f} vs {mn:,.0f}")

# --- P(malicious > normal) range in train (run2)
ps = [(rb(tr.loc[tr.label == 1, f], tr.loc[tr.label == 0, f]) + 1) / 2 for f in F]
claim("run2", "train P(mal>normal) about 0.21-0.36", "0.21-0.36", f"{min(ps):.3f}-{max(ps):.3f}", round(min(ps), 2) == 0.21 and round(max(ps), 2) == 0.36)

# --- category claims
nrm = {p: d[d.label == 0] for p, d in P.items()}


def cat_rb(p, cat, f):
    d = P[p]
    return rb(d.loc[d.attack_cat == cat, f], nrm[p][f])


g = [cat_rb("train", "Generic", f) for f in F]
claim("run1", "Generic delta about -0.7 to -0.87 (train)", "-0.70..-0.87", f"{min(g):.3f}..{max(g):.3f}", round(min(g), 2) >= -0.88 and max(g) <= -0.65)
claim("run1,run2", "Exploits dur delta +0.13 / +0.15 (train/test)", "+0.13/+0.15", f"{cat_rb('train','Exploits','dur'):+.3f}/{cat_rb('test','Exploits','dur'):+.3f}",
      round(cat_rb("train", "Exploits", "dur"), 2) == 0.13 and round(cat_rb("test", "Exploits", "dur"), 2) == 0.15)
claim("run1", "Worms dur delta +0.41 / +0.22", "+0.41/+0.22", f"{cat_rb('train','Worms','dur'):+.3f}/{cat_rb('test','Worms','dur'):+.3f}",
      round(cat_rb("train", "Worms", "dur"), 2) == 0.41 and round(cat_rb("test", "Worms", "dur"), 2) == 0.22)
sh = [cat_rb("train", "Shellcode", f) for f in F]
claim("run1", "Shellcode strongly lower than normal on most features (train)", "strongly negative", ", ".join(f"{f}={v:+.2f}" for f, v in zip(F, sh)), sum(v < -0.3 for v in sh) >= 3)
claim("run3", "Analysis dur -0.35 train vs -0.68 test", "-0.35/-0.68", f"{cat_rb('train','Analysis','dur'):+.3f}/{cat_rb('test','Analysis','dur'):+.3f}",
      round(cat_rb("train", "Analysis", "dur"), 2) == -0.35 and round(cat_rb("test", "Analysis", "dur"), 2) == -0.68)
claim("run2,run3", "Exploits dbytes -0.26 train vs +0.02 test", "-0.26/+0.02", f"{cat_rb('train','Exploits','dbytes'):+.3f}/{cat_rb('test','Exploits','dbytes'):+.3f}",
      round(cat_rb("train", "Exploits", "dbytes"), 2) == -0.26 and round(cat_rb("test", "Exploits", "dbytes"), 2) == 0.02)
claim("run3", "Pooled malicious dominated by Generic, Exploits, Fuzzers", "top-3", ", ".join(tr[tr.label == 1].attack_cat.value_counts().index[:3]),
      list(tr[tr.label == 1].attack_cat.value_counts().index[:3]) == ["Generic", "Exploits", "Fuzzers"])

# --- shared-row overlap (run2)
key = [c for c in tr.columns if c not in ("id", "label", "attack_cat")]
ov = len(tr[key].drop_duplicates().merge(te[key].drop_duplicates(), on=key))
claim("run2", "1,302 distinct feature rows in both partitions", "1302", str(ov), ov == 1302)

# --- normal-class shift KS range (run1, run3)
from scipy.stats import ks_2samp
ks = [ks_2samp(tr.loc[tr.label == 0, f], te.loc[te.label == 0, f]).statistic for f in F]
ksm = [ks_2samp(tr.loc[tr.label == 1, f], te.loc[te.label == 1, f]).statistic for f in F]
claim("run1,run3", "Normal-class KS train vs test 0.12-0.18", "0.12-0.18", f"{min(ks):.3f}-{max(ks):.3f}", round(min(ks), 2) == 0.12 and round(max(ks), 2) == 0.18)
claim("run1,run3", "Malicious-class KS <= 0.075", "<=0.075", f"{min(ksm):.3f}-{max(ksm):.3f}", max(ksm) <= 0.0755)

out = pd.DataFrame(rows)
pd.set_option("display.width", 250); pd.set_option("display.max_colwidth", 70)
print(out.to_string(index=False))
out.to_csv(HERE / "claim_audit.csv", index=False)
print("\nWRONG:", (out.verdict == "WRONG").sum(), "of", len(out))
